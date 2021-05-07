package main
//Modified from Ladongo
//Author: Jumbo
import (
	"github.com/stacktitan/smb/smb"
	"github.com/k8gege/LadonGo/port"
	"github.com/k8gege/LadonGo/dic"
	"github.com/k8gege/LadonGo/logger"
	"fmt"
	"strings"
	"os"
	"time"
	"sync"
	"strconv"
	"net"
)
//Not Support 2003
func SmbAuth(ip string, port string, username string, password string) ( result bool,err error) {
	result = false

	options := smb.Options{
		Host:        ip,
		Port:        445,
		User:        username,
		Password:    password,
		Domain:      "",
		Workstation: "",
	}

	session, err := smb.NewSession(options, false)
	if err == nil {
		session.Close()
		if session.IsAuthenticated {
			result = true
		}
	}
	return result,err
}

func SmbScan2(Target string) {
	fmt.Println("Check... "+Target+" 445.. ")
	if port.PortCheck(Target,445) {
		Loop:
		for _, u := range dic.UserDic() {
			for _, p := range dic.PassDic() {
				fmt.Println("Check... "+Target+" "+u+" "+p)
				res,err := SmbAuth(Target, "445", u, p)
				if res==true && err==nil {
					logger.PrintIsok("SmbScan",Target,u, p)
					// fmt.Println("ok : " + Target+" "+u+" "+p)
					break Loop
				}
			}
		}
	}
}

func SmbScan(Target string) {
	fmt.Println("Check... "+Target+" 445.. ")
	if port.PortCheck(Target,445) {
		if dic.UserPassIsExist() {
			Loop:
			for _, up := range dic.UserPassDic() {
				s :=strings.Split(up, " ")
				u := s[0]
				p := s[1]
				fmt.Println("Check... "+Target+" "+u+" "+p)
				res,err := SmbAuth(Target, "445", u, p)
				if res==true && err==nil {
					logger.PrintIsok("SmbScan",Target,u, p)
					// fmt.Println("ok : " + Target+" "+u+" "+p)
					break Loop
				}
				
			}
		} else {
			SmbScan2(Target)	
		}
	}
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func CScan(Target string){
	ip := strings.Replace(Target, "/c", "", -1)
	ip = strings.Replace(ip, "/C", "", -1)
	ips := strings.Split(ip,".")
	ip = ips[0]+"."+ips[1]+"."+ips[2]
	var wg sync.WaitGroup
	for i:=1;i<256;i++ {
		ip:=fmt.Sprintf("%s.%d",ip,i)
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			// fmt.Println("c: "+ip)
			SmbScan(ip);
		}(ip)
	}
	wg.Wait()
	CEnd()
}

func CEnd(){
	fmt.Println("CFinished: "+time.Now().Format("2006-01-02 03:04:05"))
	}


func End(){
	fmt.Println(" Finished: "+time.Now().Format("2006-01-02 03:04:05"))
	os.Exit(0)
	}

func BScan(Target string){
	ip:=strings.Replace(Target, "/b", "", -1)
	ip = strings.Replace(ip, "/B", "", -1)
	ips := strings.Split(ip,".")
	ip = ips[0]+"."+ips[1]
	for i:=0;i<256;i++ {
		ip:=fmt.Sprintf("%s.%d",ip,i)
		fmt.Println("\nC_Segment: "+ip)
		fmt.Println("=============================================")
		CScan(ip)
	}
}
func AScan(Target string){
	ip:=strings.Replace(Target, "/a", "", -1)
	ip = strings.Replace(ip, "/A", "", -1)
	ips := strings.Split(ip,".")
	ip = ips[0]
	for i:=0;i<256;i++ {
		ip:=fmt.Sprintf("%s.%d",ip,i)
		BScan(ip)
	}
}

func main() {
	fmt.Println("\nScanStart: "+time.Now().Format("2006-01-02 03:04:05"))
	ParLen := len(os.Args)
	Target := os.Args[ParLen-1]
	fmt.Println(Target)
	if strings.Contains(Target, "/c")||strings.Contains(Target, "/C") {
		CScan(Target)
	} else if strings.Contains(Target, "/b")||strings.Contains(Target, "/B") {
		BScan(Target)
	} else if strings.Contains(Target, "/a")||strings.Contains(Target, "/A") {
		AScan(Target)
	} else if strings.Contains(Target, "-")&&strings.Contains(Target, ".") {
			CRange := strings.Split(Target, "-")
			CIP :=strings.Split(CRange[0], ".")
			IPC :=CIP[0]+"."+CIP[1]
			SIP :=strings.Split(CRange[0], ".")[2]
			EIP :=strings.Split(CRange[1], ".")[2]
			ips, err := strconv.Atoi(SIP)
			ipe, err := strconv.Atoi(EIP)
			if err != nil {
			}
			for i:=ips;i<=ipe;i++ {
				ip:=fmt.Sprintf("%s.%d",IPC,i)
				
				fmt.Println("\nC_Segment: "+ip)
				fmt.Println("=============================================")
				CScan(ip)
				
			 }
	} else if strings.Contains(Target, "/") {
				if Target != ""  {
				ip, ipNet, err := net.ParseCIDR(Target)
				if err != nil {
					fmt.Println(Target +" invalid CIDR")
					return
				}
				var wg sync.WaitGroup
				for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
					wg.Add(1)
					go func(ip string) {
						defer wg.Done()
						SmbScan(ip)
					}(ip.String())
				}
				wg.Wait()
			}
	} else {
		SmbScan(Target)
			}
		
}