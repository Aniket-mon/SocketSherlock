<h1 align="center" id="title">SocketSherlock</h1>

<p align="center"><img src="https://socialify.git.ci/Aniket-mon/SocketSherlock/image?description=1&amp;font=KoHo&amp;forks=1&amp;issues=1&amp;language=1&amp;name=1&amp;owner=1&amp;pattern=Diagonal%20Stripes&amp;pulls=1&amp;stargazers=1&amp;theme=Dark" alt="project-image"></p>

<p id="description">SocketSherlock is a powerful, fast and user-friendly port scanning tool designed to help network administrators, security professionals, and enthusiasts investigate open ports on target IP addresses.</p>

  
  
<h2>🧐 Features</h2>

Here're some of the project's best features:

*   Scan multiple IP addresses simultaneously
*   Customizable port range scanning
*   Fast and efficient multi-threaded scanning
*   Detailed output with port status and associated services
*   Option to save results in JSON format
*   User-friendly command-line interface
*   Run directly from the terminal

<h2>🛠️ Installation Steps:</h2>

<p>1. Clone the repository :</p>

```
git clone https://github.com/Aniket-mon/SocketSherlock.git
```

<p>2. Navigate to the project directory:</p>

```
cd SocketSherlock
```

<p>3. Install the required dependencies</p>

```
pip install -r requirements.txt
```
<h2>🪝Usage </h2>

<p>Basic usage:</p>

```
python SocketSherlock.py <target ip>
```

<p>2. Navigate to the project directory:</p>

```
python SocketSherlock.py <target ip> [arguments]
```

### Options

- `-p, --ports`: Specify port range to scan (e.g., `1-1000` or `80,443,8080`)
- `-t, --timeout`: Set timeout for each port scan (default: 1.0s)
- `-o, --output`: Specify output file for JSON results
- `-h, --help`: Show help message and exit

### Examples

1. Scan a single IP address with default settings:
   ```
   python socketsherlock.py 192.168.1.1
   ```

2. Scan multiple IP addresses with specific ports:
   ```
   python socketsherlock.py 192.168.1.1,10.0.0.1 -p 80,443,8080
   ```

3. Scan an IP address with a custom port range and timeout:
   ```
   python socketsherlock.py 192.168.1.1 -p 1-1000 -t 0.5
   ```

4. Save scan results to a JSON file:
   ```
   python socketsherlock.py 192.168.1.1 -o results.json

<h2>🍰 Contribution Guidelines:</h2>

Please contribute using GitHub Flow. 
Create a branch. 
Add commits. 
Create a pull request.

  
  
<h2>💻 Built with</h2>

Technologies used in the project:

Language :
  * Python
    
Libraries :
  * sys
  * socket
  * typing
  * ipaddress
  * prettytable
  * agrparse
  * concurrent.futures - ThreadPoolExecutor
  * tqdm
  * json
  

<h2>🛡️ License:</h2>

This project is licensed under the MIT License

<h2>💖Acknowledgemnets</h2>

* Thanks to all contributors who have helped to improve SocketSherlock. 

* Special thanks to the open-source community for providing the libraries and tools that made this project possible.



For more information and updates, please visit the [SocketSherlock GitHub repository](https://github.com/Aniket-mon/SocketSherlock).
