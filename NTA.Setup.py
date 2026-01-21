# NetWatch-Packet-Analyzer


Step 1: VS Code aur Python Setup karein
Python Install karein: Agar aapke PC mein Python nahi hai, toh python.org se download karke install karein. Installation ke waqt "Add Python to PATH" checkmark zaroor karein.

VS Code Extension: VS Code kholein, left side mein Extensions icon (char squares) par click karein aur "Python" (Microsoft waala) install karein.

Step 2: Npcap Install karein (Windows Users ke liye)
Scapy library ko network interface access karne ke liye Npcap ki zaroorat hoti hai.

Npcap Download Link par jayein aur "Npcap installer" download karke install karein.

Note: Install karte waqt "Install Npcap in WinPcap API-compatible Mode" wale option ko tick rehne dein.

Step 3: Project Folder aur File Banayein
Apne computer par ek naya folder banayein, jaise NetworkProject.

VS Code mein jayein: File > Open Folder aur apna folder select karein.

Ab ek nayi file banayein, naam rakhein: netwatch.py.

Pichle response mein diya gaya Full Python GUI Code is file mein paste kar dein aur Ctrl + S se save karein.

Step 4: Library Install karein
VS Code ke andar niche diye gaye Terminal ko kholein (Ctrl + ~) aur ye command likhein:

Bash
pip install scapy
Step 5: VS Code ko "Administrator" mode mein Run karein (Sabse Zaroori Step)
Normal mode mein VS Code ko network packets capture karne ki permission nahi milti. Iske liye:

VS Code ko band karein.

Apne Desktop ya Start Menu mein VS Code icon par Right-click karein.

"Run as Administrator" select karein.

Ab wahi folder aur file dobara kholein.

Step 6: Project ko Run karein
Apni netwatch.py file par jayein.

Top right corner mein jo Play Button (Run Python File) hai, us par click karein.

Ya phir terminal mein type karein:

Bash
python netwatch.py
Step 7: Testing aur Output
Program ka GUI window khul jayega.

Dropdown se "ALL" ya "TCP" select karein.

"Start Sniffing" button par click karein.

Ab apna browser kholein aur koi bhi website visit karein. Aap dekhenge ki VS Code ke niche wale area mein packets live dikhne lagenge.

Data save karne ke liye "Export CSV" par click karein.
