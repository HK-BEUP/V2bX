package limiter

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/format"
	"github.com/InazumaV/V2bX/conf"
	"github.com/juju/ratelimit"
)

var limitLock sync.RWMutex
var limiter map[string]*Limiter

func Init() {
	limiter = map[string]*Limiter{}
}

type Limiter struct {
	mu            sync.Mutex
	ownerInfo     map[int]*UserLimitInfo
	DomainRules   []*regexp.Regexp
	ProtocolRules []string
	SpeedLimit    int
	UserOnlineIP  *sync.Map      // Key: TagUUID, value: {Key: Ip, value: Uid}
	OldUserOnline *sync.Map      // Key: Ip, value: Uid
	UUIDtoUID     map[string]int // Key: UUID, value: Uid
	UserLimitInfo *sync.Map      // Key: TagUUID value: UserLimitInfo
	SpeedLimiter  *sync.Map      // key: owner UID, value: *ratelimit.Bucket
	AliveList     map[int]int    // Key: Uid, value: alive_ip
}

type UserLimitInfo struct {
	UID               int
	SpeedLimit        int
	DeviceLimit       int
	DynamicSpeedLimit int
	ExpireTime        int64
	OverLimit         bool
}

func AddLimiter(tag string, l *conf.LimitConfig, users []panel.UserInfo, aliveList map[int]int) *Limiter {
	info := &Limiter{
		SpeedLimit:    l.SpeedLimit,
		ownerInfo:     make(map[int]*UserLimitInfo),
		UserOnlineIP:  new(sync.Map),
		UserLimitInfo: new(sync.Map),
		SpeedLimiter:  new(sync.Map),
		AliveList:     aliveList,
		OldUserOnline: new(sync.Map),
	}
	uuidmap := make(map[string]int)
	for i := range users {
		uuidmap[users[i].Uuid] = users[i].Id
		userLimit := info.ownerInfo[users[i].Id]
		if userLimit == nil {
			userLimit = &UserLimitInfo{}
			info.ownerInfo[users[i].Id] = userLimit
		}
		userLimit.UID = users[i].Id
		if users[i].SpeedLimit != 0 {
			userLimit.SpeedLimit = users[i].SpeedLimit
		}
		if users[i].DeviceLimit != 0 {
			userLimit.DeviceLimit = users[i].DeviceLimit
		}
		userLimit.OverLimit = false
		info.UserLimitInfo.Store(format.UserTag(tag, users[i].Uuid), userLimit)
	}
	info.UUIDtoUID = uuidmap
	limitLock.Lock()
	limiter[tag] = info
	limitLock.Unlock()
	return info
}

func GetLimiter(tag string) (info *Limiter, err error) {
	limitLock.RLock()
	info, ok := limiter[tag]
	limitLock.RUnlock()
	if !ok {
		return nil, errors.New("not found")
	}
	return info, nil
}

func DeleteLimiter(tag string) {
	limitLock.Lock()
	delete(limiter, tag)
	limitLock.Unlock()
}

func (l *Limiter) UpdateUser(tag string, added []panel.UserInfo, deleted []panel.UserInfo) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range deleted {
		l.UserLimitInfo.Delete(format.UserTag(tag, deleted[i].Uuid))
		l.UserOnlineIP.Delete(format.UserTag(tag, deleted[i].Uuid))
		// Keep the shared account bucket when removing only one credential.
		delete(l.UUIDtoUID, deleted[i].Uuid)
		// Other credentials retain the same account-level alive count.
	}
	// Remove a bucket only when this owner has no remaining or incoming credential.
	for _, removed := range deleted {
		remains := false
		for _, uid := range l.UUIDtoUID {
			if uid == removed.Id {
				remains = true
				break
			}
		}
		if !remains {
			for _, next := range added {
				if next.Id == removed.Id {
					remains = true
					break
				}
			}
		}
		if !remains {
			l.SpeedLimiter.Delete(accountBucketKey(removed.Id))
			delete(l.AliveList, removed.Id)
			delete(l.ownerInfo, removed.Id)
		}
	}
	for i := range added {
		next := added[i]
		userLimit := l.ownerInfo[next.Id]
		if userLimit == nil {
			userLimit = &UserLimitInfo{UID: next.Id}
			l.ownerInfo[next.Id] = userLimit
		}
		if userLimit.SpeedLimit != next.SpeedLimit {
			l.SpeedLimiter.Delete(accountBucketKey(next.Id))
		}
		userLimit.SpeedLimit = next.SpeedLimit
		userLimit.DeviceLimit = next.DeviceLimit
		l.UserLimitInfo.Store(format.UserTag(tag, next.Uuid), userLimit)
		l.UUIDtoUID[next.Uuid] = next.Id
	}
}

func (l *Limiter) UpdateDynamicSpeedLimit(tag, uuid string, limit int, expire time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if v, ok := l.UserLimitInfo.Load(format.UserTag(tag, uuid)); ok {
		info := v.(*UserLimitInfo)
		l.SpeedLimiter.Delete(accountBucketKey(info.UID))
		info.DynamicSpeedLimit = limit
		info.ExpireTime = expire.Unix()
	} else {
		return errors.New("not found")
	}
	return nil
}

func (l *Limiter) CheckLimit(taguuid string, ip string, isTcp bool, noSSUDP bool) (Bucket *ratelimit.Bucket, Reject bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// check if ipv4 mapped ipv6
	ip = strings.TrimPrefix(ip, "::ffff:")

	// check and gen speed limit Bucket
	nodeLimit := l.SpeedLimit
	userLimit := 0
	deviceLimit := 0
	var uid int
	if v, ok := l.UserLimitInfo.Load(taguuid); ok {
		u := v.(*UserLimitInfo)
		deviceLimit = u.DeviceLimit
		uid = u.UID
		if u.ExpireTime < time.Now().Unix() && u.ExpireTime != 0 {
			u.DynamicSpeedLimit = 0
			u.ExpireTime = 0
			l.SpeedLimiter.Delete(accountBucketKey(uid))
		}
		userLimit = determineSpeedLimit(u.SpeedLimit, u.DynamicSpeedLimit)
	} else {
		return nil, true
	}
	if noSSUDP {
		// Store online user for device limit
		newipMap := new(sync.Map)
		newipMap.Store(ip, uid)
		aliveIp := l.AliveList[uid]
		// If any device is online
		if v, loaded := l.UserOnlineIP.LoadOrStore(taguuid, newipMap); loaded {
			oldipMap := v.(*sync.Map)
			// If this is a new ip
			if _, loaded := oldipMap.LoadOrStore(ip, uid); !loaded {
				if v, loaded := l.OldUserOnline.Load(ip); loaded {
					if v.(int) == uid {
						l.OldUserOnline.Delete(ip)
					}
				} else if deviceLimit > 0 {
					if deviceLimit <= aliveIp {
						oldipMap.Delete(ip)
						return nil, true
					}
				}
			}
		} else if v, ok := l.OldUserOnline.Load(ip); ok {
			if v.(int) == uid {
				l.OldUserOnline.Delete(ip)
			}
		} else {
			if deviceLimit > 0 {
				if deviceLimit <= aliveIp {
					l.UserOnlineIP.Delete(taguuid)
					return nil, true
				}
			}
		}
	}

	limit := int64(determineSpeedLimit(nodeLimit, userLimit)) * 1000000 / 8 // If you need the Speed limit
	if limit > 0 {
		Bucket = ratelimit.NewBucketWithQuantum(time.Second, limit, limit) // Byte/s
		if v, ok := l.SpeedLimiter.LoadOrStore(accountBucketKey(uid), Bucket); ok {
			return v.(*ratelimit.Bucket), false
		} else {
			l.SpeedLimiter.Store(accountBucketKey(uid), Bucket)
			return Bucket, false
		}
	} else {
		return nil, false
	}
}

func (l *Limiter) GetOnlineDevice() (*[]panel.OnlineUser, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var onlineUser []panel.OnlineUser
	seen := make(map[panel.OnlineUser]bool)
	l.OldUserOnline = new(sync.Map)
	l.UserOnlineIP.Range(func(key, value interface{}) bool {
		taguuid := key.(string)
		ipMap := value.(*sync.Map)
		ipMap.Range(func(key, value interface{}) bool {
			uid := value.(int)
			ip := key.(string)
			l.OldUserOnline.Store(ip, uid)
			entry := panel.OnlineUser{UID: uid, IP: ip}
			if !seen[entry] {
				seen[entry] = true
				onlineUser = append(onlineUser, entry)
			}
			return true
		})
		l.UserOnlineIP.Delete(taguuid) // Reset online device
		return true
	})

	return &onlineUser, nil
}

type UserIpList struct {
	Uid    int      `json:"Uid"`
	IpList []string `json:"Ips"`
}

func accountBucketKey(uid int) string { return "owner:" + strconv.Itoa(uid) }

func (l *Limiter) UpdateAliveList(alive map[int]int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.AliveList = alive
}
