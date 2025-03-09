

🚀 Project Name : grep-backURLs
===============

![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-purple.svg)
<a href="https://goreportcard.com/report/github.com/gigachad80/grep-backURLs"><img src="https://goreportcard.com/badge/github.com/gigachad80/grep-backURLs"></a>
<a href="https://github.com/gigachad80/grep-backURLs/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>

#### grep-backURLs : Automated way to find juicy information from website 

### 📌 Overview


 *_grep-backURLs_* is a web security automation tool to extracts important credentials in bug hunting. It uses subfinder to find subdomains and then those subdomain acts as input links for waybackurls . After that , it uses grep command and keywords.txt to sort out important credentials.

### 🤔 Why This Name?

 Just beacuse it uses grep command to sort out from waybackURLs link.


### ⌚ Total Time taken to build & test

 Approx 3-3:30 hr.

### 🙃Why I Created This

 Cause I don't want to waste my time to find subdomains and then try each keyword from keyword.txt to check whether is there any credential or not, so decided to automate it.

### 📚  Requirements & Dependencies

* #### Golang
* #### [waybackurls](https://github.com/tomnomnom/waybackurls)
* #### [subfinder](https://github.com/projectdiscovery/subfinder)

### 📥 Installation Guide

#### ⚡ Quick Install:

 1. Git clone this URL.
 2. Go to grep-backURls directory and give permission to main.go
 3. Run command ./main.go

### 💓 Credits:


 * #### [@tomnomnom](https://github.com/tomnomnom) for developing waybackurls
* ####  [@project discovery](https://github.com/projectdiscovery)for creating subfinder.
* #### Sathvik and his [video](https://www.youtube.com/watch?v=lp4Do_VIwzw)  for inspiration. 



### 📞 Contact


 📧 Email: pookielinuxuser@tutamail.com


### 📄 License

Licensed under **MIT**

🕒 Last Updated: January 18, 2025 
