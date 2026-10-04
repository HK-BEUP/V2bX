package limiter

import (
	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/format"
	"github.com/InazumaV/V2bX/conf"
	"sync"
	"testing"
	"time"
)

func TestIndependentCredentialsShareOwnerBandwidthBucket(t *testing.T) {
	Init()
	tag := "subscription-test"
	users := []panel.UserInfo{{Id: 11, Uuid: "legacy", SpeedLimit: 10}, {Id: 11, Uuid: "grant-a", SpeedLimit: 10}, {Id: 11, Uuid: "grant-b", SpeedLimit: 10}, {Id: 12, Uuid: "other", SpeedLimit: 10}}
	l := AddLimiter(tag, &conf.LimitConfig{}, users, map[int]int{11: 1})
	defer DeleteLimiter(tag)
	a, deny := l.CheckLimit(format.UserTag(tag, "legacy"), "192.0.2.1", true, false)
	if deny || a == nil {
		t.Fatal("legacy rejected")
	}
	b, _ := l.CheckLimit(format.UserTag(tag, "grant-a"), "192.0.2.2", true, false)
	c, _ := l.CheckLimit(format.UserTag(tag, "grant-b"), "192.0.2.3", true, false)
	other, _ := l.CheckLimit(format.UserTag(tag, "other"), "192.0.2.4", true, false)
	if a != b || a != c || a == other {
		t.Fatal("account bandwidth fragmented or shared across owners")
	}
	l.UpdateUser(tag, nil, []panel.UserInfo{users[1]})
	legacy, _ := l.CheckLimit(format.UserTag(tag, "legacy"), "192.0.2.1", true, false)
	if legacy != a || l.AliveList[11] != 1 {
		t.Fatal("removing one grant reset sibling account limit")
	}
	if _, deny = l.CheckLimit(format.UserTag(tag, "grant-a"), "192.0.2.2", true, false); !deny {
		t.Fatal("removed grant allowed")
	}
	l.UpdateUser(tag, []panel.UserInfo{users[1]}, nil)
	restored, _ := l.CheckLimit(format.UserTag(tag, "grant-a"), "192.0.2.2", true, false)
	if restored != a {
		t.Fatal("restored grant bypassed account bucket")
	}
}
func TestCredentialAliasesDoNotMultiplySameNetworkCount(t *testing.T) {
	Init()
	tag := "subscription-count"
	l := AddLimiter(tag, &conf.LimitConfig{}, []panel.UserInfo{{Id: 1, Uuid: "a"}, {Id: 1, Uuid: "b"}, {Id: 2, Uuid: "c"}}, nil)
	defer DeleteLimiter(tag)
	for _, u := range []string{"a", "b", "c"} {
		if _, deny := l.CheckLimit(format.UserTag(tag, u), "192.0.2.1", true, true); deny {
			t.Fatal("allowed alias denied")
		}
	}
	got, err := l.GetOnlineDevice()
	if err != nil || len(*got) != 2 {
		t.Fatalf("network counted as devices: %#v %v", got, err)
	}
}

func TestSubscriptionPlanAndDynamicLimitChangesStayShared(t *testing.T) {
	Init()
	tag := "subscription-plan"
	users := []panel.UserInfo{{Id: 11, Uuid: "legacy", SpeedLimit: 10}, {Id: 11, Uuid: "grant", SpeedLimit: 10}}
	l := AddLimiter(tag, &conf.LimitConfig{}, users, nil)
	defer DeleteLimiter(tag)
	old, _ := l.CheckLimit(format.UserTag(tag, "legacy"), "192.0.2.1", true, false)
	next := append([]panel.UserInfo(nil), users...)
	for i := range next {
		next[i].SpeedLimit = 2
	}
	l.UpdateUser(tag, next, users)
	a, _ := l.CheckLimit(format.UserTag(tag, "legacy"), "192.0.2.1", true, false)
	b, _ := l.CheckLimit(format.UserTag(tag, "grant"), "192.0.2.2", true, false)
	if a == old || a != b || a.Rate() != 250000 {
		t.Fatal("plan limit update not applied once to owner")
	}
	if err := l.UpdateDynamicSpeedLimit(tag, "grant", 1, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	a, _ = l.CheckLimit(format.UserTag(tag, "legacy"), "192.0.2.1", true, false)
	b, _ = l.CheckLimit(format.UserTag(tag, "grant"), "192.0.2.2", true, false)
	if a != b || a.Rate() != 125000 {
		t.Fatal("alias bypassed dynamic owner limit")
	}
	if err := l.UpdateDynamicSpeedLimit(tag, "grant", 1, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	a, _ = l.CheckLimit(format.UserTag(tag, "legacy"), "192.0.2.1", true, false)
	b, _ = l.CheckLimit(format.UserTag(tag, "grant"), "192.0.2.2", true, false)
	if a != b || a.Rate() != 250000 {
		t.Fatal("dynamic expiry failed to restore shared plan")
	}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				l.CheckLimit(format.UserTag(tag, "grant"), "192.0.2.2", true, true)
			}
		}()
	}
	for j := 0; j < 100; j++ {
		l.UpdateAliveList(map[int]int{11: 1})
		l.UpdateDynamicSpeedLimit(tag, "legacy", 1, time.Now().Add(time.Minute))
		l.GetOnlineDevice()
	}
	wg.Wait()
}
