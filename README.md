# Netwrok-traffic-sniffer-2
checks suspicious ip through wireshark tshark and points it out

install bash and python3
<img width="1193" height="622" alt="image" src="https://github.com/user-attachments/assets/1eaa42f2-22fb-46ad-9d62-a5b1d2d06393" />

install basic tools like wireshark tshark
<img width="737" height="208" alt="image" src="https://github.com/user-attachments/assets/0e249fad-5040-4aeb-8df8-249d2f8cd3ff" />

installing tools like pyshark - python wrapper for tshark which analyzes the packet captured , scikit-learn - organizes the clusstered data and makes it understandable , pandas - makes spreadsheets and tabular coloumn
got an error while doing it 
<img width="1370" height="493" alt="image" src="https://github.com/user-attachments/assets/0b41d896-e83a-481d-bec4-2515c4ce91e0" />

so the error is saying that its externally managed in order to continue we need to make a virtual environment 
installing python3-venv to create a virtual environment 
<img width="773" height="152" alt="image" src="https://github.com/user-attachments/assets/d37ab9d1-4f92-4cf4-bcb2-9e962480a4fb" />

we make a directory (or) making a separate folder where we will store our data
<img width="1080" height="370" alt="image" src="https://github.com/user-attachments/assets/c7568686-b1cc-4fcb-a853-7f7d9c1c9524" />

an error came in between that the venv(virtual environment) created , but didnt get activate ,
<img width="731" height="447" alt="image" src="https://github.com/user-attachments/assets/6e29ae11-53f1-42aa-9401-f743e7e055ff" />

installing tools in the virtual environment
<img width="1273" height="342" alt="image" src="https://github.com/user-attachments/assets/6b1d6d7c-49ef-4f8c-8b37-89d9a29f9ecb" />
the process in line 10 can be ignored if you are solely doing it in virtual environment 

install git and gitclone the python file for automation
<img width="852" height="316" alt="image" src="https://github.com/user-attachments/assets/ab5d7184-99ec-41da-9893-8d1a374a5520" />

get inside the file and make it run 
<img width="1038" height="212" alt="image" src="https://github.com/user-attachments/assets/854b804f-6e57-4b23-962e-6080ea2f6e96" />
in order to see packets, u need to open any browser or , in another terminal you need to ping "192.168.4.1.."{this is the usual avivity done by hackers to get into your system, burst of ipaddresses}
get inside your python code and 
<img width="902" height="291" alt="image" src="https://github.com/user-attachments/assets/04c1af39-741a-4249-9000-34104851654e" />

now run the automation which you created (in my case i have used an ai automated code which fetches it's data from wireshark and displays it in the terminal for now , orelse can make a different interface at localhost or a workable online link
<img width="1297" height="126" alt="image" src="https://github.com/user-attachments/assets/bb9b1ec9-7662-4b31-b520-ebd12d4fd68b" />

[ recieved an error to list the interface as we didn't speicfy it earlier ]

running it again with the specified network interface name {we used -i to exactly point at eth0 instead of toggling to different network interfaces}
<img width="1373" height="342" alt="image" src="https://github.com/user-attachments/assets/72902b7e-5d70-45e2-be5f-5be3609cbf86" />

installing flask on the virtual environment to make it represantable 
<img width="1352" height="213" alt="image" src="https://github.com/user-attachments/assets/6fcc790b-e0d0-4cd1-96b2-4dcfa521f559" />

after installing flask we install dashboard to input the code for making the table - the code pasted will be in the branch named ,"Dashboard code".

make directory for the template which we are going to create , in html - the code of html is present in the process branch , file named as HTML code
<img width="752" height="286" alt="image" src="https://github.com/user-attachments/assets/8524c548-c46f-40bb-b39a-a2cd7e8fcc98" />

