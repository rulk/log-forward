FROM golang
ADD ./src /go/src

RUN go get gopkg.in/fatih/pool.v2

RUN go build -o /go/main /go/src/main/main.go

WORKDIR /go