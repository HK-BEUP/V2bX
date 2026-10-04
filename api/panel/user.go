package panel

import (
"context"
	"fmt"
"io"
	"math"
	"strings"

	"encoding/json/jsontext"
	"encoding/json/v2"

	"github.com/vmihailenco/msgpack/v5"
)

type OnlineUser struct {
	UID int
	IP  string
}

type UserInfo struct {
	Id                int    `json:"id" msgpack:"id"`
	Uuid              string `json:"uuid" msgpack:"uuid"`
	SpeedLimit        int    `json:"speed_limit" msgpack:"speed_limit"`
	DeviceLimit       int    `json:"device_limit" msgpack:"device_limit"`
	SubscriptionGrant string `json:"subscription_grant,omitempty" msgpack:"subscription_grant,omitempty"`
}

type UserListBody struct {
	Users []UserInfo `json:"users" msgpack:"users"`
}

type AliveMap struct {
	Alive map[int]int `json:"alive"`
}

// GetUserList will pull user from v2board
func (c *Client) GetUserList() ([]UserInfo, error) { return c.GetUserListContext(context.Background()) }
func (c *Client) GetUserListContext(ctx context.Context) ([]UserInfo, error) {
	const path = "/api/v1/server/UniProxy/user"
	request := c.client.R().SetContext(ctx)
	if c.trafficEpoch != "" {
		request.SetHeader("X-Beup-Traffic-Epoch", c.trafficEpoch)
	}
	r, err := request.
		SetHeader("If-None-Match", c.userEtag).
		SetHeader("X-Response-Format", "msgpack").
		SetHeader("X-Beup-Subscription-Grants", "1").
		SetDoNotParseResponse(true).
		Get(path)
	if r == nil || r.RawResponse == nil {
		return nil, fmt.Errorf("received nil response or raw response")
	}
	defer r.RawResponse.Body.Close()
 // Legacy admission shares the settlement lock. Read only a small explicit
 // error code; do not decode an error as an authoritative empty user list.
 if c.legacyAccounting && err == nil && r.StatusCode() == 409 {
  body, readErr := io.ReadAll(io.LimitReader(r.RawResponse.Body, 1025))
  var rejection struct { Code string `json:"code"` }
  if readErr == nil && len(body) <= 1024 && json.Unmarshal(body, &rejection) == nil && rejection.Code == "traffic_settling" {
   return nil, ErrLegacySettlementBusy
  }
  return nil, fmt.Errorf("legacy user list conflict")
 }


	if c.trafficEpoch != "" && r.Header().Get("X-Beup-Traffic-Epoch") != c.trafficEpoch {
		return nil, fmt.Errorf("panel did not acknowledge the accounting generation")
	}
	if r.StatusCode() == 304 {
		return nil, nil
	}

	if err = c.checkResponse(r, path, err); err != nil {
		return nil, err
	}
	userlist := &UserListBody{Users: []UserInfo{}}
	if strings.Contains(r.Header().Get("Content-Type"), "application/x-msgpack") {
		decoder := msgpack.NewDecoder(r.RawResponse.Body)
		if err := decoder.Decode(userlist); err != nil {
			return nil, fmt.Errorf("decode user list error: %w", err)
		}
	} else {
		dec := jsontext.NewDecoder(r.RawResponse.Body)
		for {
			tok, err := dec.ReadToken()
			if err != nil {
				return nil, fmt.Errorf("decode user list error: %w", err)
			}
			if tok.Kind() == '"' && tok.String() == "users" {
				break
			}
		}
		tok, err := dec.ReadToken()
		if err != nil {
			return nil, fmt.Errorf("decode user list error: %w", err)
		}
		if tok.Kind() != '[' {
			return nil, fmt.Errorf(`decode user list error: expected "users" array`)
		}
		for dec.PeekKind() != ']' {
			val, err := dec.ReadValue()
			if err != nil {
				return nil, fmt.Errorf("decode user list error: read user object: %w", err)
			}
			var u UserInfo
			if err := json.Unmarshal(val, &u); err != nil {
				return nil, fmt.Errorf("decode user list error: unmarshal user error: %w", err)
			}
			userlist.Users = append(userlist.Users, u)
		}
	}
	c.userEtag = r.Header().Get("ETag")
	return userlist.Users, nil
}

// GetUserAlive will fetch the alive_ip count for users
func (c *Client) GetUserAlive() (map[int]int, error) { return c.GetUserAliveContext(context.Background()) }
func (c *Client) GetUserAliveContext(ctx context.Context) (map[int]int, error) {
	c.AliveMap = &AliveMap{}
	const path = "/api/v1/server/UniProxy/alivelist"
	r, err := c.client.R().SetContext(ctx).
		ForceContentType("application/json").
		Get(path)
	if (c.trafficEpoch != "" || c.legacyAccounting) && (err != nil || r == nil || r.StatusCode() >= 399) { return nil, fmt.Errorf("reliable online list request failed") }
 if err != nil || r == nil || r.StatusCode() >= 399 {
		c.AliveMap.Alive = make(map[int]int)
		return c.AliveMap.Alive, nil
	}
	if r == nil || r.RawResponse == nil {
		fmt.Printf("received nil response or raw response")
		c.AliveMap.Alive = make(map[int]int)
		return c.AliveMap.Alive, nil
	}
	defer r.RawResponse.Body.Close()
	if err := json.Unmarshal(r.Body(), c.AliveMap); err != nil {
		fmt.Printf("unmarshal user alive list error: %s", err)
		c.AliveMap.Alive = make(map[int]int)
	}

	return c.AliveMap.Alive, nil
}

type UserTraffic struct {
	UID      int
	Upload   int64
	Download int64
}

// ReportUserTraffic reports the user traffic
func (c *Client) ReportUserTraffic(userTraffic []UserTraffic) error {
 if c.trafficEpoch != "" || c.legacyAccounting { return fmt.Errorf("unidentified traffic reporting disabled") }
	data, aggregateErr := aggregateUserTraffic(userTraffic)
	if aggregateErr != nil {
		return aggregateErr
	}
	const path = "/api/v1/server/UniProxy/push"
	r, err := c.client.R().
		SetBody(data).
		ForceContentType("application/json").
		Post(path)
	err = c.checkResponse(r, path, err)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) ReportNodeOnlineUsers(data *map[int][]string) error { return c.ReportNodeOnlineUsersContext(context.Background(), data) }
func (c *Client) ReportNodeOnlineUsersContext(ctx context.Context, data *map[int][]string) error {
	const path = "/api/v1/server/UniProxy/alive"
	r, err := c.client.R().SetContext(ctx).
		SetBody(data).
		ForceContentType("application/json").
		Post(path)
	err = c.checkResponse(r, path, err)

	if err != nil { return err }
 return nil
}

// Independent credentials retain their owner UID. Never overwrite an earlier credential.
func aggregateUserTraffic(rows []UserTraffic) (map[int][]int64, error) {
	out := make(map[int][]int64, len(rows))
	for _, row := range rows {
		if row.UID < 1 || row.Upload < 0 || row.Download < 0 {
			return nil, fmt.Errorf("invalid account traffic")
		}
		sum, ok := out[row.UID]
		if !ok {
			sum = []int64{0, 0}
		}
		if row.Upload > math.MaxInt64-sum[0] || row.Download > math.MaxInt64-sum[1] {
			return nil, fmt.Errorf("account traffic overflow")
		}
		sum[0] += row.Upload
		sum[1] += row.Download
		out[row.UID] = sum
	}
	return out, nil
}
