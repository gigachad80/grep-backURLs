

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


### ⌚ Total Time taken to develop , test & building bin.

 Approx 3 hr 48 min 58 sec 

### 🙃Why I Created This

 Cause I don't want to waste my time to find subdomains and then try each keyword from keyword.txt to check whether is there any credential or not, so decided to automate it.

### 📚  Requirements & Dependencies

* #### Golang
* #### [waybackurls](https://github.com/tomnomnom/waybackurls)
* #### [subfinder](https://github.com/projectdiscovery/subfinder)

### 📥 Installation Guide & USage : 

#### ⚡ Quick Install:

 1. Git clone this URL.
 2. Go to grep-backURls directory and give permission to main.go
 3. Run command ./main.go

 OR 

 - You can directly download the binary from releases section [here](https://github.com/gigachad80/grep-backURLs/releases)


### 🍃 Usage :


```
A tool to find sensitive information by enumerating subdomains, collecting Wayback Machine URLs,
analyzing them, and matching against custom patterns.

Options:
  -config
        Run interactive configuration setup and exit
  -domain string
        Specify the target domain (e.g., example.com)
  -html
        Generate a comprehensive HTML report summarizing all findings in the current directory
  -json
        Generate results in JSON format for each pattern
  -keywords-file string
        Path to a file containing grep-like keywords (one per line) (default "grep_keywords.txt")
  -markdown
        Generate results in Markdown format for each pattern
  -output-dir string
        Base directory to store all scan output files (default "output")
  -v    Display the tool version and exit (shorthand)
  -version
        Display the tool version and exit

```

### Note : 

> You don't need to specify -json or -markdown flag , it will automatically generate both , no matter you have specified these flags for not . However , for HTML report , you need to specify -html flag . 

> For Customisation : edit config.json in your editor ( pluma / notepad / nano / vim 😉)

### 💫 What's new  in grep-backURLs v2  : 

- Customisation and control over concurrency , output directory name , timeout for subdomain enum , customm keywords , logging . 

- HTML report , JSON , Markdown support



### 📝 Roadmap / To-do 

- [ ] Release Cross Platform Executables 
- [ ] Add More Keywords 
- [x] Output in JSON & Markdown format
- [x] HTML Report 
- [ ] Attach Demo Screenshot 
- [ ] Update Readme


### 💓 Credits:


 * #### [@tomnomnom](https://github.com/tomnomnom) for developing waybackurls
* ####  [@project discovery](https://github.com/projectdiscovery)for creating subfinder.
* #### Sathvik and his [video](https://www.youtube.com/watch?v=lp4Do_VIwzw)  for inspiration. 



### 📞 Contact


 📧 Email: pookielinuxuser@tutamail.com


### 📄 License

Licensed under **MIT**

🕒 Last Updated: May 25 , 2025 

🕒 First Published : January ,  2025
