package beuptransfer

import (
 "bufio"
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "io"
 "net/http"
 "os"
 "os/exec"
 "strings"
 "testing"
 "time"
)

func TestPHPControlExchange(t *testing.T){
 script:=os.Getenv("BEUP_TRANSFER_PHP_CONTROL_QA");if script==""{t.Skip("explicit synthetic PHP fixture required")}
 ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second);defer cancel()
 cmd:=exec.CommandContext(ctx,"php",script);var stderr bytes.Buffer;cmd.Stderr=&stderr;in,err:=cmd.StdinPipe();if err!=nil{t.Fatal(err)};out,err:=cmd.StdoutPipe();if err!=nil{t.Fatal(err)}
 if err=cmd.Start();err!=nil{t.Fatal(err)};defer func(){in.Close();if e:=cmd.Wait();e!=nil{t.Errorf("PHP fixture failed: %v %s",e,stderr.String())}}()
 lines:=bufio.NewReader(out);line,err:=lines.ReadString('\n');if err!=nil||line!="READY\n"{t.Fatalf("fixture not ready: %v %s %s",err,line,stderr.String())}
 scope:="vless-256";h:=sha256.Sum256([]byte(scope));epoch:=hex.EncodeToString(h[:])[:32]
 c,err:=NewHTTPControl("https://panel.example.invalid/control","https://panel.example.invalid/probe",scope,bytes.Repeat([]byte{9},32));if err!=nil{t.Fatal(err)}
 bridge:=roundTripFunc(func(req *http.Request)(*http.Response,error){
  body,e:=io.ReadAll(req.Body);if e!=nil{return nil,e};purpose:=strings.TrimPrefix(req.URL.Path,"/")
  wire,_:=json.Marshal(map[string]any{"purpose":purpose,"body":string(body),"headers":map[string]string{"time":req.Header.Get("X-Beup-Time"),"nonce":req.Header.Get("X-Beup-Nonce"),"signature":req.Header.Get("X-Beup-Signature")}})
  if _,e=in.Write(append(wire,'\n'));e!=nil{return nil,e};line,e:=lines.ReadString('\n');if e!=nil{return nil,fmt.Errorf("PHP reply: %w",e)}
  var reply map[string]string;if e=json.Unmarshal([]byte(line),&reply);e!=nil{return nil,e};headers:=http.Header{};headers.Set("X-Beup-Time",reply["time"]);headers.Set("X-Beup-Nonce",reply["nonce"]);headers.Set("X-Beup-Signature",reply["signature"])
  return &http.Response{StatusCode:200,Header:headers,Body:io.NopCloser(strings.NewReader(reply["body"])),Request:req},nil
 });c.poll.client.Transport=bridge;c.probe.client.Transport=bridge
 commands,err:=c.Poll(ctx,epoch);if err!=nil||len(commands)!=1||commands[0].Kind!="probe"{t.Fatal("PHP command not parsed",err)}
 if err=c.Probe(ctx,commands[0],ProbeStatus{TrackingReady:true,Bindings:1});err!=nil{t.Fatal("PHP probe rejected",err)}
 commands,err=c.Poll(ctx,epoch);if err!=nil||len(commands)!=0{t.Fatal("verified probe repeated",err)}
}
