FROM golang:1.14.6
RUN mkdir /app
ADD . /app
WORKDIR /app
RUN go get -u github.com/dgrijalva/jwt-go
RUN go get -u github.com/labstack/echo
RUN go build -o main .
CMD ["/app/main"]
