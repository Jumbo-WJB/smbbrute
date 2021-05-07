从LadonGo剥离出来的smb爆破工具
## 编译方式
CGO_ENABLED=0 GOOS=windows GOARCH=amd64  go build -ldflags "-s -w"  smbbrute.go
## 再用upx压缩下
yum install upx
upx ./smbbrute.exe
