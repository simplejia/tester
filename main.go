package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"math/rand"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/simplejia/utils"

	"bufio"
	"bytes"
	"log"
	"net/http"
	"sync"
)

type Conf struct {
	Vars struct {
		Shuffle   bool     // 接口调用是否打乱
		Timeout   string   // http请求超时
		Keepalive bool     // http是否保持长连接
		Step      int      // 精度，越大精度越高
		Total     int      // 从日志里解析单个接口最大个数
		Sampling  int      // 输出日志采样
		RetOks    []string // 代表接口调用成功
		Filters   []string // 过滤掉的接口返回
		Ips       []string // 压测机ip列表
	}
	Rates map[string]int
}

type CODE string

const (
	OK      CODE = "ok"
	TIMEOUT      = "timeout"
	_5XX         = "5xx"
	_4XX         = "4xx"
	_3XX         = "3xx"
	LOGIC        = "logic"
	OTHER        = "other"
	TOTAL        = "total"
)

var (
	conf *Conf
	reqs = make(map[string][][]byte)

	codes = [...]CODE{OK, TIMEOUT, _5XX, _4XX, _3XX, LOGIC, OTHER, TOTAL}
	cnts  = make(map[CODE]map[string]*uint32)
	chs   = make(map[string]chan []byte)

	client *http.Client // reuse for better
)

func parseConf() {
	fcontent, err := ioutil.ReadFile("conf.json")
	if err != nil {
		log.Fatalln(err)
	}
	fcontent = utils.RemoveAnnotation(fcontent)
	if err = json.Unmarshal(fcontent, &conf); err != nil {
		log.Fatalln(err)
	}

	log.Println("conf:", utils.Iprint(conf))
}

func shuffle(d [][]byte) {
	for i := len(d) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		d[i], d[j] = d[j], d[i]
	}
	return
}

func loadData(f string) {
	log.Println("begin load api log file")

	r := regexp.MustCompile(`^{"lv":"INFO".+?"rq":"(.+?)->(.+?)".+?"io":"orig_purifier","data":({.+?})`)

	fs := strings.Split(f, ",")
	reqss := make([]map[string][][]byte, len(fs))
	var wg sync.WaitGroup
	for fpos := range fs {
		wg.Add(1)
		go func(fpos int) {
			defer func() {
				log.Println("end load api log file:", fs[fpos])
				wg.Done()
			}()
			f := fs[fpos]
			file, err := os.Open(f)
			if err != nil {
				log.Fatalf("load api log file: %s, error: %v", f, err)
			}
			reader := bufio.NewReader(file)
			for {
				line, err := reader.ReadBytes('\n')
				if err == io.EOF {
					break
				} else if err != nil {
					log.Fatalf("read api log file: %s, error: %v\n", f, err)
				}
				matches := r.FindSubmatch(line)
				if matches == nil {
					continue
				}
				module, action, body := string(matches[1]), string(matches[2]), matches[3]
				ma := strings.ToLower(module + "/" + action)
				// 不在rates配置里就剔除
				if _, ok := conf.Rates[ma]; !ok {
					continue
				}
				_reqs := reqss[fpos]
				if _reqs == nil {
					_reqs = make(map[string][][]byte)
					reqss[fpos] = _reqs
				}
				if len(_reqs[ma]) >= conf.Vars.Total {
					continue
				}
				_reqs[ma] = append(_reqs[ma], body)
			}
		}(fpos)
	}
	wg.Wait()

	for i := range reqss {
		for k, v := range reqss[i] {
			reqs[k] = append(reqs[k], v...)
		}
	}

	for ma, rate := range conf.Rates {
		log.Printf("ma: %s, num: %d, rate: %d",
			ma, len(reqs[ma]), rate)
	}

	// if need shuffle reqs?
	if conf.Vars.Shuffle {
		for _, vs := range reqs {
			shuffle(vs)
		}
	}

	// debug
	//log.Printf("debug reqs: %s\n", utils.Iprint(reqs))

	log.Println("end load api log file")
}

func initCnts() {
	for _, code := range codes {
		m := make(map[string]*uint32)
		for ma := range reqs {
			var i uint32
			m[ma] = &i
		}
		cnts[code] = m
	}
	for ma := range reqs {
		chs[ma] = make(chan []byte, conf.Vars.Sampling)
	}
}

func pushCh(ma string, data []byte) {
	select {
	case chs[ma] <- data:
	default:
	}
}

func initClient() {
	timeout, err := time.ParseDuration(conf.Vars.Timeout)
	if err != nil {
		log.Fatalln(err)
	}
	client = &http.Client{
		Timeout: timeout,
	}
}

func post(body []byte, ma string) {
	ips := conf.Vars.Ips
	if len(ips) == 0 {
		atomic.AddUint32(cnts[OTHER][ma], 1)
		pushCh(ma, []byte(fmt.Sprintf("post no ip found, body: %s, ma: %s", body, ma)))
		return
	}

	ip := ips[rand.Intn(len(ips))]
	uri := fmt.Sprintf("http://%s/%s", ip, ma)
	req, err := http.NewRequest(http.MethodPost, uri, bytes.NewReader(body))
	if err != nil {
		atomic.AddUint32(cnts[OTHER][ma], 1)
		pushCh(ma, []byte(fmt.Sprintf("http.NewRequest err: %v, body: %s, ma: %s", err, body, ma)))
		return
	}
	if !conf.Vars.Keepalive {
		req.Close = true
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			atomic.AddUint32(cnts[TIMEOUT][ma], 1)
		} else {
			atomic.AddUint32(cnts[OTHER][ma], 1)
			pushCh(ma, []byte(fmt.Sprintf("net err: %v, body: %s, ma: %s, ip: %s", err, body, ma, ip)))
		}
		return
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		atomic.AddUint32(cnts[OTHER][ma], 1)
		pushCh(ma, []byte(err.Error()))
		return
	}
	if g, e := resp.StatusCode, http.StatusOK; g != e {
		switch {
		case g >= 300 && g < 400:
			atomic.AddUint32(cnts[_3XX][ma], 1)
		case g >= 400 && g < 500:
			atomic.AddUint32(cnts[_4XX][ma], 1)
		case g >= 500 && g < 600:
			atomic.AddUint32(cnts[_5XX][ma], 1)
		default:
			atomic.AddUint32(cnts[OTHER][ma], 1)
			pushCh(ma, []byte(fmt.Sprintf("other status code: %d, body: %s, ma: %s, respBody: %s, ip: %s", g, body, ma, respBody, ip)))
		}
		return
	}

	codeOk := false
	for _, retOk := range conf.Vars.RetOks {
		if bytes.HasPrefix(respBody, []byte(retOk)) {
			codeOk = true
			break
		}
	}
	if codeOk {
		atomic.AddUint32(cnts[OK][ma], 1)
	} else {
		atomic.AddUint32(cnts[LOGIC][ma], 1)
		filtered := false
		for _, filter := range conf.Vars.Filters {
			if bytes.HasPrefix(respBody, []byte(filter)) {
				filtered = true
				break
			}
		}
		if !filtered {
			pushCh(ma, []byte(fmt.Sprintf("ret error, body: %s, ma: %s, respBody: %s, ip: %s", body, ma, respBody, ip)))
		}
	}
}

func tick(num int, times float64) {
	for ma, vs := range reqs {
		go func(ma string, vs [][]byte) {
			rate := conf.Rates[ma]
			rate = int(times / float64(num) * float64(rate))
			if rate <= 0 {
				log.Fatal("rate not expect error")
			}

			step := int(math.Ceil(float64(rate) / float64(conf.Vars.Step)))
			dur := time.Duration(int(time.Second) / rate * step)
			tick := time.Tick(dur)
			i := uint(0)
			for {
				select {
				case <-tick:
					for k := 0; k < step; k++ {
						j := i % uint(len(vs))
						i++
						go post(vs[j], ma)
					}
					atomic.AddUint32(cnts[TOTAL][ma], uint32(step))
				}
			}
		}(ma, vs)
	}
}

func logerr() {
	sortedMA := []string{}
	for ma := range reqs {
		sortedMA = append(sortedMA, ma)
	}
	sort.Strings(sortedMA)

	tickNum := 0
	step := 3
	tick := time.Tick(time.Second * time.Duration(step))
	for {
		select {
		case <-tick:
			tickNum++
			for _, code := range codes {
				log.Println("status:", code)
				mas := cnts[code]
				for _, ma := range sortedMA {
					v := mas[ma]
					cnt := atomic.LoadUint32(v)
					if cnt == 0 {
						continue
					}
					log.Printf("ma: %s, cnt: %d, qps: %d, tick: %d\n", ma, cnt, int(cnt)/tickNum/step, tickNum*step)
				}
				println()
			}

			println()

			for _, ma := range sortedMA {
				ch := chs[ma]
				for i, j := 0, len(ch); i < j; i++ {
					v := <-ch
					log.Printf("ma: %s, other err: %s\n", ma, v)
				}
			}
		}
	}
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {
	var f string
	flag.StringVar(&f, "f", "api.log", "api log file, seperate by ','")
	var num int
	flag.IntVar(&num, "num", 1, "choose number of tester")
	var times float64
	flag.Float64Var(&times, "times", 1, "choose times")
	var dur string
	flag.StringVar(&dur, "dur", "30s", "time duration")

	flag.Parse()

	parseConf()

	loadData(f)

	initCnts()

	initClient()

	go tick(num, times)

	go logerr()

	d, err := time.ParseDuration(dur)
	if err != nil {
		log.Fatalln(err)
	}

	time.Sleep(d)
}
