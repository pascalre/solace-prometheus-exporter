package main

import (
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) != 4 {
		log.Println("Usage: go run endpointOwnershipStatistics.go <broker-uri> <username> <password>")
		os.Exit(1)
	}
	var brokerURI = os.Args[1]
	var username = os.Args[2]
	var password = os.Args[3]

	log.SetFlags(0)

	queueStats(brokerURI, username, password)
	topicEndpointStats(brokerURI, username, password)
}

type StatsItem struct {
	Name      string
	Vpn       string
	Owner     string
	BindCount float64
}

func queueStats(brokerURI string, username string, password string) {
	type Data struct {
		RPC struct {
			Show struct {
				Queue struct {
					Queues struct {
						Queue []struct {
							QueueName string `xml:"name"`
							Info      struct {
								MsgVpnName string  `xml:"message-vpn"`
								Quota      float64 `xml:"quota"`
								Usage      float64 `xml:"current-spool-usage-in-mb"`
								Owner      string  `xml:"owner"`
								BindCount  float64 `xml:"bind-count"`
							} `xml:"info"`
						} `xml:"queue"`
					} `xml:"queues"`
				} `xml:"queue"`
			} `xml:"show"`
		} `xml:"rpc"`
		MoreCookie struct {
			RPC string `xml:",innerxml"`
		} `xml:"more-cookie"`
		ExecuteResult struct {
			Result string `xml:"code,attr"`
			Reason string `xml:"reason,attr"`
		} `xml:"execute-result"`
	}

	extractor := func(body io.Reader, brokerURI string) (string, []StatsItem, error) {
		decoder := xml.NewDecoder(body)
		var target Data
		err := decoder.Decode(&target)
		if err != nil {
			//nolint:gosec // G706: Log injection via taint analysis
			log.Println("Can't decode QueueDetailsSemp1", "err", err, "broker", brokerURI)
			return "", nil, err
		}
		if target.ExecuteResult.Result != "ok" {
			//nolint:gosec // G706: Log injection via taint analysis
			log.Println("Can't scrape QueueDetailsSemp1", "err", err, "broker", brokerURI)
			return "", nil, fmt.Errorf("bad result: %s", target.ExecuteResult.Reason)
		}

		var items []StatsItem
		for _, queue := range target.RPC.Show.Queue.Queues.Queue {
			items = append(items, StatsItem{
				Name:      queue.QueueName,
				Vpn:       queue.Info.MsgVpnName,
				Owner:     queue.Info.Owner,
				BindCount: queue.Info.BindCount,
			})
		}
		return target.MoreCookie.RPC, items, nil
	}

	stats := processPages(brokerURI, username, password, "<rpc><show><queue><name>*</name><vpn-name>*</vpn-name><detail/><count/><num-elements>100</num-elements></queue></show></rpc>", "QueueDetailsSemp1", extractor)
	printStats(stats, "Owner", "queues")
}

func topicEndpointStats(brokerURI string, username string, password string) {
	type Data struct {
		RPC struct {
			Show struct {
				TopicEndpoint struct {
					TopicEndpoints struct {
						TopicEndpoint []struct {
							TopicEndpointName string `xml:"name"`
							Info              struct {
								MsgVpnName string  `xml:"message-vpn"`
								Quota      float64 `xml:"quota"`
								Usage      float64 `xml:"current-spool-usage-in-mb"`
								Owner      string  `xml:"owner"`
								BindCount  float64 `xml:"bind-count"`
							} `xml:"info"`
						} `xml:"topic-endpoint"`
					} `xml:"topic-endpoints"`
				} `xml:"topic-endpoint"`
			} `xml:"show"`
		} `xml:"rpc"`
		MoreCookie struct {
			RPC string `xml:",innerxml"`
		} `xml:"more-cookie"`
		ExecuteResult struct {
			Result string `xml:"code,attr"`
			Reason string `xml:"reason,attr"`
		} `xml:"execute-result"`
	}

	extractor := func(body io.Reader, brokerURI string) (string, []StatsItem, error) {
		decoder := xml.NewDecoder(body)
		var target Data
		err := decoder.Decode(&target)
		if err != nil {
			//nolint:gosec // G706: Log injection via taint analysis
			log.Println("Can't decode TopicEndpointDetailsSemp1", "err", err, "broker", brokerURI)
			return "", nil, err
		}
		if target.ExecuteResult.Result != "ok" {
			//nolint:gosec // G706: Log injection via taint analysis
			log.Println("Can't scrape TopicEndpointDetailsSemp1", "err", err, "broker", brokerURI)
			return "", nil, fmt.Errorf("bad result: %s", target.ExecuteResult.Reason)
		}

		var items []StatsItem
		for _, te := range target.RPC.Show.TopicEndpoint.TopicEndpoints.TopicEndpoint {
			items = append(items, StatsItem{
				Name:      te.TopicEndpointName,
				Vpn:       te.Info.MsgVpnName,
				Owner:     te.Info.Owner,
				BindCount: te.Info.BindCount,
			})
		}
		return target.MoreCookie.RPC, items, nil
	}

	stats := processPages(brokerURI, username, password, "<rpc><show><topic-endpoint><name>*</name><vpn-name>*</vpn-name><detail/><count/><num-elements>100</num-elements></topic-endpoint></show></rpc>", "TopicEndpointDetailsSemp1", extractor)
	printStats(stats, "TopicEndpoint", "TopicEndpoints")
}

func processPages(brokerURI, username, password, initialRequest, logName string, extractor func(io.Reader, string) (string, []StatsItem, error)) map[string][]StatsItem {
	statsMap := make(map[string][]StatsItem)
	var lastKey = ""
	var page = 1

	for nextRequest := initialRequest; nextRequest != ""; {
		var items []StatsItem
		var err error

		nextRequest, items, err = func(req string) (string, []StatsItem, error) {
			//nolint:gosec // G706: Log injection via taint analysis
			body, err := postHTTP(brokerURI+"/SEMP", "application/xml", req, username, password, logName, page)
			page++

			if err != nil {
				//nolint:gosec // G706: Log injection via taint analysis
				log.Println("Can't scrape "+logName, "err", err, "broker", brokerURI)
				return "", nil, err
			}
			defer body.Close()
			return extractor(body, brokerURI)
		}(nextRequest)

		if err != nil {
			return statsMap
		}

		for _, item := range items {
			key := item.Vpn + "___" + item.Name
			if key == lastKey {
				continue
			}
			lastKey = key
			statsMap[item.Owner] = append(statsMap[item.Owner], item)
		}
	}
	return statsMap
}

func printStats(statsMap map[string][]StatsItem, ownerLabel string, totalLabel string) {
	var total int
	for key, value := range statsMap {
		log.Printf("%s %s has %d queues\n", ownerLabel, key, len(value))
		total += len(value)
	}
	log.Printf("Total number of %s: %d\n", totalLabel, total)

	for key, value := range statsMap {
		log.Printf("Owner %s has:\n", key)
		for _, q := range value {
			log.Printf("\t%s\n", q.Name)
		}
	}
}

func postHTTP(uri string, _ string, body string, username string, password string, logName string, page int) (io.ReadCloser, error) {
	//start := time.Now()
	var httpClient = newHTTPClient()

	//nolint:gosec // G704: SSRF via taint analysis
	req, err := http.NewRequest("POST", uri, strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(username, password)

	//nolint:gosec // G704: SSRF via taint analysis
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	//var queryDuration = time.Since(start)
	//log.Println("Scraped "+logName, "page", page, "duration", queryDuration)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("HTTP status %d (%s)", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	return resp.Body, nil
}

func newHTTPClient() http.Client {
	proxy := http.ProxyFromEnvironment

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false, MinVersion: tls.VersionTLS12},
		Proxy:           proxy,
	}
	client := http.Client{
		Timeout:   30 * time.Second,
		Transport: tr,
	}

	return client
}
