package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-ini/ini"
	"github.com/go-ldap/ldap"
)

const (
	DefaultCnf = "/../etc/ldapasswd.ini"
)

type LdapManager struct {
	Conn    *ldap.Conn
	Ldap    LdapServer
	Organiz OrganizationalUnit
	Posix   PosixFile
}

type LdapServer struct {
	User     string
	Password string
	Address  string
	Port     string
}

type OrganizationalUnit struct {
	BaseDN string
}

type PosixFile struct {
	Passwd     string
	PasswdBase string
	Shadow     string
	ShadowBase string
	Group      string
	GroupBase  string
}

type UserInfo struct {
	Uid           string
	UidNumber     string
	GidNumber     string
	HomeDirectory string
	LoginShell    string
	UserPassword  string
}

type GroupInfo struct {
	Gid       string
	GidNumber string
	MemberUid string
}

var ldapManager LdapManager

func init() {
	dir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	configFile := dir + DefaultCnf

	cfg, err := ini.Load(configFile)
	if err != nil {
		fmt.Printf("Fail to read file: %v\n", err)
	} else {
		ldapManager.Ldap.User = cfg.Section("Ldap").Key("Username").String()
		ldapManager.Ldap.Password = cfg.Section("Ldap").Key("Password").String()
		ldapManager.Ldap.Address = cfg.Section("Ldap").Key("Address").String()
		ldapManager.Ldap.Port = cfg.Section("Ldap").Key("Port").String()

		ldapManager.Organiz.BaseDN = cfg.Section("Organiz").Key("BaseDN").String()

		ldapManager.Posix.Passwd = cfg.Section("Posix").Key("Passwd").String()
		ldapManager.Posix.PasswdBase = cfg.Section("Posix").Key("PasswdBase").String()

		ldapManager.Posix.Shadow = cfg.Section("Posix").Key("Shadow").String()
		ldapManager.Posix.ShadowBase = cfg.Section("Posix").Key("ShadowBase").String()

		ldapManager.Posix.Group = cfg.Section("Posix").Key("Group").String()
		ldapManager.Posix.GroupBase = cfg.Section("Posix").Key("GroupBase").String()

	}
}

func (ldapManage LdapManager) GetLdapUsers() (users []UserInfo, err error) {
	sql := ldap.NewSearchRequest(ldapManage.Organiz.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(objectClass=%s)", "posixAccount"),
		[]string{"uid", "uidNumber", "gidNumber", "homeDirectory", "loginShell", "userPassword"},
		nil)

	cur, err := ldapManage.Conn.Search(sql)
	if err != nil {
		return users, err
	}

	for _, entry := range cur.Entries {
		var user UserInfo
		for _, attribute := range entry.Attributes {
			if attribute.Name == "uid" {
				user.Uid = strings.Join(attribute.Values, ",")
			}
			if attribute.Name == "uidNumber" {
				user.UidNumber = strings.Join(attribute.Values, ",")
			}
			if attribute.Name == "gidNumber" {
				user.GidNumber = strings.Join(attribute.Values, ",")
			}
			if attribute.Name == "homeDirectory" {
				user.HomeDirectory = strings.Join(attribute.Values, ",")
			}
			if attribute.Name == "loginShell" {
				user.LoginShell = strings.Join(attribute.Values, ",")
			}
		}
		users = append(users, user)
	}
	return users, err
}

func (ldapManage LdapManager) GetLdapGroups() (groups []GroupInfo, err error) {
	sql := ldap.NewSearchRequest(ldapManage.Organiz.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(objectClass=%s)", "posixGroup"),
		[]string{"cn", "gidNumber", "memberUid"},
		nil)

	cur, err := ldapManage.Conn.Search(sql)
	if err != nil {
		return groups, err
	}

	for _, entry := range cur.Entries {
		var group GroupInfo
		for _, attribute := range entry.Attributes {
			if attribute.Name == "cn" {
				group.Gid = strings.Join(attribute.Values, ",")
			}
			if attribute.Name == "gidNumber" {
				group.GidNumber = strings.Join(attribute.Values, ",")
			}
			if attribute.Name == "memberUid" {
				group.MemberUid = strings.Join(attribute.Values, ",")
			}
		}
		groups = append(groups, group)
	}
	return groups, err
}

func (p PosixFile) FlushPasswd(usersLdap []UserInfo) (err error) {
	var boolRebuild bool
	var passwdsTotal []UserInfo
	if FileExist(p.Passwd) {
		content, err := FileRead(p.Passwd)
		if err != nil {
			return err
		}
		var passwdsExist []UserInfo
		for _, rowPasswd := range strings.Split(content, "\n") {
			if rowPasswd != "" {
				var userInfo UserInfo
				for i, v := range strings.Split(rowPasswd, ":") {
					switch i {
					case 0:
						userInfo.Uid = v
					case 2:
						userInfo.UidNumber = v
					case 3:
						userInfo.GidNumber = v
					case 5:
						userInfo.HomeDirectory = v
					case 6:
						userInfo.LoginShell = v
					}
				}
				passwdsExist = append(passwdsExist, userInfo)
			}
		}

		var passwdsBase []UserInfo
		if FileExist(p.PasswdBase) {
			content, err := FileRead(p.PasswdBase)
			if err != nil {
				return err
			}
			for _, rowPasswd := range strings.Split(content, "\n") {
				if rowPasswd != "" {
					var userInfo UserInfo
					for i, v := range strings.Split(rowPasswd, ":") {
						switch i {
						case 0:
							userInfo.Uid = v
						case 2:
							userInfo.UidNumber = v
						case 3:
							userInfo.GidNumber = v
						case 5:
							userInfo.HomeDirectory = v
						case 6:
							userInfo.LoginShell = v
						}
					}
					passwdsBase = append(passwdsBase, userInfo)
				}
			}
			passwdsTotal = append(passwdsTotal, passwdsBase...)
		}
		passwdsTotal = append(passwdsTotal, usersLdap...)

		var passwdsExistBase []UserInfo
		var passwdsExistLdap []UserInfo
		for _, passwdExist := range passwdsExist {
			for _, passwdBase := range passwdsBase {
				if passwdExist.UidNumber == passwdBase.UidNumber {
					if passwdExist.Uid == passwdBase.Uid && passwdExist.GidNumber == passwdBase.GidNumber && passwdExist.HomeDirectory == passwdBase.HomeDirectory {
						passwdsExistBase = append(passwdsExistBase, passwdExist)
					}
				}
			}

			for _, user := range usersLdap {
				if passwdExist.UidNumber == user.UidNumber {
					if passwdExist.Uid == user.Uid && passwdExist.GidNumber == user.GidNumber && passwdExist.HomeDirectory == user.HomeDirectory {
						passwdsExistLdap = append(passwdsExistLdap, user)
					}
				}
			}
		}

		//删除重构
		if len(passwdsExistLdap) != len(usersLdap) {
			log.Println(fmt.Sprintf("FlushPasswd: passwdsExistLdap[%v],usersLdap[%v]", len(passwdsExistLdap), len(usersLdap)))
			boolRebuild = true
		}

		//base更新重构
		if len(passwdsExistBase) != len(passwdsBase) {
			log.Println(fmt.Sprintf("FlushPasswd: passwdsExistBase[%v],passwdsBase[%v]", len(passwdsExistBase), len(passwdsBase)))
			boolRebuild = true
		}

		//脏数据重构
		if len(passwdsExist) != len(passwdsBase)+len(usersLdap) {
			log.Println(fmt.Sprintf("FlushPasswd: passwdsExist[%v],passwdsBase[%v],usersLdap[%v]", len(passwdsExist), len(passwdsBase), len(usersLdap)))
			boolRebuild = true
		}
	} else {
		log.Println(fmt.Sprintf("FlushPasswd:[%s]Not exist", p.Passwd))
		boolRebuild = true
	}

	if boolRebuild {
		file, err := os.OpenFile(p.Passwd, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		defer file.Close()

		if FileExist(p.PasswdBase) {
			content, err := FileRead(p.PasswdBase)
			if err != nil {
				return err
			}
			if !strings.HasSuffix(content, "\n") {
				content += "\n"
			}
			re := regexp.MustCompile(`\n+`)
			content = re.ReplaceAllString(content, "\n")

			_, err = io.WriteString(file, content)
			if err != nil {
				return err
			}
		}

		for _, user := range usersLdap {
			rowPasswd := fmt.Sprintf("%s:x:%s:%s::%s:%s\n", user.Uid, user.UidNumber, user.GidNumber, user.HomeDirectory, user.LoginShell)
			_, err = io.WriteString(file, rowPasswd)
			if err != nil {
				return err
			}
		}
	}

	return err
}

func (p PosixFile) FlushShadow(usersLdap []UserInfo) (err error) {
	var boolRebuild bool
	var shadowsTotal []UserInfo
	if FileExist(p.Shadow) {
		content, err := FileRead(p.Shadow)
		if err != nil {
			return err
		}
		var shadowsExist []UserInfo
		for _, rowShadow := range strings.Split(content, "\n") {
			if rowShadow != "" {
				var userInfo UserInfo
				for i, v := range strings.Split(rowShadow, ":") {
					if i == 0 && v != "" {
						userInfo.Uid = v
						shadowsExist = append(shadowsExist, userInfo)
					}
				}
			}
		}

		var shadowsBase []UserInfo
		if FileExist(p.ShadowBase) {
			content, err := FileRead(p.ShadowBase)
			if err != nil {
				return err
			}
			for _, rowShadow := range strings.Split(content, "\n") {
				if rowShadow != "" {
					var userInfo UserInfo
					for i, v := range strings.Split(rowShadow, ":") {
						if i == 0 && v != "" {
							userInfo.Uid = v
							shadowsBase = append(shadowsBase, userInfo)
						}
					}
				}
			}
			shadowsTotal = append(shadowsTotal, shadowsBase...)
		}
		shadowsTotal = append(shadowsTotal, usersLdap...)

		var shadowsExistBase []UserInfo
		var shadowsExistLdap []UserInfo
		for _, shadowExist := range shadowsExist {
			for _, shadowBase := range shadowsBase {
				if shadowExist.Uid == shadowBase.Uid {
					shadowsExistBase = append(shadowsExistBase, shadowExist)
				}
			}

			for _, user := range usersLdap {
				if shadowExist.Uid == user.Uid {
					shadowsExistLdap = append(shadowsExistLdap, user)
				}
			}
		}

		//删除重构
		if len(shadowsExistLdap) != len(usersLdap) {
			log.Println(fmt.Sprintf("FlushShadow: shadowsExistLdap[%v],usersLdap[%v]", len(shadowsExistLdap), len(usersLdap)))
			boolRebuild = true
		}

		//base更新重构
		if len(shadowsExistBase) != len(shadowsBase) {
			log.Println(fmt.Sprintf("FlushShadow: shadowsExistBase[%v],shadowsBase[%v]", len(shadowsExistBase), len(shadowsBase)))
			boolRebuild = true
		}

		//脏数据重构
		if len(shadowsExist) != len(shadowsBase)+len(usersLdap) {
			log.Println(fmt.Sprintf("FlushShadow: shadowsExist[%v],shadowsBase[%v],usersLdap[%v]", len(shadowsExist), len(shadowsBase), len(usersLdap)))
			boolRebuild = true
		}
	} else {
		log.Println(fmt.Sprintf("FlushShadow:[%s]Not exist", p.Shadow))
		boolRebuild = true
	}

	if boolRebuild {
		file, err := os.OpenFile(p.Shadow, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		defer file.Close()

		if FileExist(p.ShadowBase) {
			content, err := FileRead(p.ShadowBase)
			if err != nil {
				return err
			}
			if !strings.HasSuffix(content, "\n") {
				content += "\n"
			}
			re := regexp.MustCompile(`\n+`)
			content = re.ReplaceAllString(content, "\n")

			_, err = io.WriteString(file, content)
			if err != nil {
				return err
			}
		}

		for _, user := range usersLdap {
			rowShadow := fmt.Sprintf("%s:?:19495:0:99999:7:::\n", user.Uid)
			_, err = io.WriteString(file, rowShadow)
			if err != nil {
				return err
			}
		}
	}
	return err
}

func (p PosixFile) FlushGroups(groupsLdap []GroupInfo) (err error) {
	var boolRebuild bool
	var groupsTotal []GroupInfo
	if FileExist(p.Group) {
		content, err := FileRead(p.Group)
		if err != nil {
			return err
		}
		var groupsExist []GroupInfo
		for _, rowGroup := range strings.Split(content, "\n") {
			if rowGroup != "" {
				var groupInfo GroupInfo
				for i, v := range strings.Split(rowGroup, ":") {
					switch i {
					case 0:
						groupInfo.Gid = v
					case 2:
						groupInfo.GidNumber = v
					case 3:
						groupInfo.MemberUid = v
					}
				}
				groupsExist = append(groupsExist, groupInfo)
			}
		}

		var groupsBase []GroupInfo
		if FileExist(p.GroupBase) {
			content, err := FileRead(p.GroupBase)
			if err != nil {
				return err
			}
			for _, rowGroup := range strings.Split(content, "\n") {
				if rowGroup != "" {
					var groupInfo GroupInfo
					for i, v := range strings.Split(rowGroup, ":") {
						switch i {
						case 0:
							groupInfo.Gid = v
						case 2:
							groupInfo.GidNumber = v
						case 3:
							groupInfo.MemberUid = v
						}
					}
					groupsBase = append(groupsBase, groupInfo)
				}
			}
			groupsTotal = append(groupsTotal, groupsBase...)
		}
		groupsTotal = append(groupsTotal, groupsLdap...)

		var groupsExistBase []GroupInfo
		var groupsExistLdap []GroupInfo
		for _, groupExist := range groupsExist {
			for _, groupBase := range groupsBase {
				if groupExist.GidNumber == groupBase.GidNumber && groupExist.Gid == groupBase.Gid && groupExist.MemberUid == groupBase.MemberUid {
					groupsExistBase = append(groupsExistBase, groupExist)
				}
			}

			for _, group := range groupsLdap {
				if groupExist.GidNumber == group.GidNumber && groupExist.Gid == group.Gid && groupExist.MemberUid == group.MemberUid {
					groupsExistLdap = append(groupsExistLdap, group)
				}
			}
		}

		//删除重构
		if len(groupsExistLdap) != len(groupsLdap) {
			log.Println(fmt.Sprintf("FlushGroup: groupsExistLdap[%v],groupsLdap[%v]", len(groupsExistLdap), len(groupsLdap)))
			boolRebuild = true
		}

		//base更新重构
		if len(groupsExistBase) != len(groupsBase) {
			log.Println(fmt.Sprintf("FlushGroup: groupsExistBase[%v],groupsBase[%v]", len(groupsExistBase), len(groupsBase)))
			boolRebuild = true
		}

		//脏数据重构
		if len(groupsExist) != len(groupsBase)+len(groupsLdap) {
			log.Println(fmt.Sprintf("FlushGroup: groupsExist[%v],groupsBase[%v],groupsLdap[%v]", len(groupsExist), len(groupsBase), len(groupsLdap)))
			boolRebuild = true
		}
	} else {
		log.Println(fmt.Sprintf("FlushGroup:[%s]Not exist", p.Group))
		boolRebuild = true
	}

	if boolRebuild {
		file, err := os.OpenFile(p.Group, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		defer file.Close()

		if FileExist(p.GroupBase) {
			content, err := FileRead(p.GroupBase)
			if err != nil {
				return err
			}
			if !strings.HasSuffix(content, "\n") {
				content += "\n"
			}
			re := regexp.MustCompile(`\n+`)
			content = re.ReplaceAllString(content, "\n")

			_, err = io.WriteString(file, content)
			if err != nil {
				return err
			}
		}

		for _, group := range groupsLdap {
			rowGroup := fmt.Sprintf("%s:x:%s:%s\n", group.Gid, group.GidNumber, group.MemberUid)
			_, err = io.WriteString(file, rowGroup)
			if err != nil {
				return err
			}
		}
	}
	return err
}

func main() {
	if ldapManager.Posix.Passwd == "" {
		log.Fatal(fmt.Sprintf("FAILURE: Passwd undefined[%s]!", ldapManager.Posix.Passwd))
	}

	if ldapManager.Posix.Shadow == "" {
		log.Fatal(fmt.Sprintf("FAILURE: Shadow undefined[%s]!", ldapManager.Posix.Shadow))
	}

	if ldapManager.Posix.Group == "" {
		log.Fatal(fmt.Sprintf("FAILURE: Group undefined[%s]!", ldapManager.Posix.Group))
	}

	url := fmt.Sprintf("%s:%s", ldapManager.Ldap.Address, ldapManager.Ldap.Port)
	conn, err := ldap.Dial("tcp", url)
	if err != nil {
		log.Fatal(fmt.Sprintf("FAILURE: Ldap server disconnect[%s]%s", url, err.Error()))
	}

	defer conn.Close()

	err = conn.Bind(fmt.Sprintf("cn=%s,%s", ldapManager.Ldap.User, ldapManager.Organiz.BaseDN), ldapManager.Ldap.Password)
	if err != nil {
		log.Fatal(fmt.Sprintf("FAILURE: Ldap server bind[%s]", err.Error()))
	}
	ldapManager.Conn = conn

	users, err := ldapManager.GetLdapUsers()
	if err != nil {
		log.Fatal(fmt.Sprintf("FAILURE: GetLdapUsers[%s]", err.Error()))
	}
	err = ldapManager.Posix.FlushPasswd(users)
	if err != nil {
		log.Fatal(fmt.Sprintf("FAILURE: FlushPasswd[%s]", err.Error()))
	}
	err = ldapManager.Posix.FlushShadow(users)
	if err != nil {
		log.Fatal(fmt.Sprintf("FAILURE: FlushShadow[%s]", err.Error()))
	}

	groups, err := ldapManager.GetLdapGroups()
	if err != nil {
		log.Fatal(fmt.Sprintf("FAILURE: GetLdapGroups[%s]", err.Error()))
	}
	err = ldapManager.Posix.FlushGroups(groups)
	if err != nil {
		log.Fatal(fmt.Sprintf("FAILURE: FlushUsers[%s]", err.Error()))
	}
}

func FileExist(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil || os.IsExist(err)
}

func FileRead(path string) (string, error) {
	fi, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer fi.Close()
	bytes, err := ioutil.ReadAll(fi)
	return string(bytes), err
}
