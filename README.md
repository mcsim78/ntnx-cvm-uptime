# HOW TO USE
1. Install the latest Python3 version from https://www.python.org/downloads/
2. unzip the archive and cd into the directory
3. python -m venv venv
4. source venv/bin/activate (for linux) or venv\Scripts\activate.bat (for windows)
5. pip install -r requirements.txt
6. python main.py

# FOR WHAT?
Sometimes I'd like to know how many days my CVMs are running and how many memory they are using. 
This information needed to decide when will need to reboot some CVMs. 
Script connects by Prism Element IP to the CVM, gathering information about the SVMs IPs and collects uptime and available memory from them.

