# 🧠 Personal OSINT Breach Scanner

### 🔍 Overview  
The **Personal OSINT Breach Scanner** is an open-source intelligence (OSINT) tool that queries multiple public data breach APIs, correlates possible breach sources, and visualizes them through an interactive mind map.  
It is designed to help users identify potential breach vectors and understand exposure risks, supported by a dedicated **mitigation and prevention** section for proactive security improvement.

---

### ⚙️ Core Features  

- **🔗 API Integration:**  
  Integrates with multiple breach intelligence sources such as:  
  - HaveIBeenPwned  
  - Dehashed  
  - Leak-Lookup  
  - BreachDirectory  

- **🧩 Mind Map Visualization:**  
  Displays breach sources and relationships as a **dynamic visual graph**, highlighting affected domains, user accounts, and breach categories.

- **🛡️ General Mitigation Guidance:**  
  Provides generalized mitigation and prevention strategies after correlation results, ensuring applicable security recommendations for personal or organizational use.

- **📦 Modular and Extensible Design:**  
  The backend, API handlers, and visualization logic are structured for easy modification and expansion.

---

### 🧰 Tech Stack  

| Layer | Technology Used |
|-------|------------------|
| **Frontend** | HTML, CSS, JavaScript (D3.js / Cytoscape.js) |
| **Backend** | Python (Flask) |
| **API Handling** | REST (requests library for breach queries) |
| **Data Handling** | JSON-based correlation model |
| **Deployment** | Localhost / Docker compatible |

---

### 🧠 Flow Overview  

1. **User Input:**  
   User provides an email, domain, or breach source for scanning.  

2. **API Query:**  
   The system performs real-time lookups through connected OSINT breach APIs.  

3. **Correlation Engine:**  
   Extracts and correlates related breach sources, timestamps, and categories.  

4. **Visualization:**  
   Renders an interactive mind map to represent the connections and severity visually.  

5. **General Mitigation Section:**  
   Displays comprehensive security best practices and mitigation strategies relevant to the findings.

---

### 🛠️ Setup & Usage  

#### **1. Clone Repository**
```bash
git clone https://github.com/Tarun167/Personal-OSINT-Breach-Scanner.git
cd Personal-OSINT-Breach-Scanner
```

#### **2. Install Dependencies**
```bash
pip install -r requirements.txt
```

#### **3. Configure API Keys**
Create a `.env` file and include your API credentials:
```
DEHASHED_API_KEY=your_key_here
HIBP_API_KEY=your_key_here
```

#### **4. Run the Application**
```bash
python app.py
```
Access it locally at: [https://127.0.0.1:5000](https://127.0.0.1:5000)

---

### 🧱 General Mitigation & Prevention Practices  

- Use **unique, strong passwords** for all accounts  
- Enable **Multi-Factor Authentication (MFA)** wherever possible  
- Regularly **update software and systems** to patch vulnerabilities  
- Utilize **data encryption** for sensitive information  
- Segment networks to isolate critical systems  
- **Monitor breach alerts** and subscribe to trusted threat intelligence feeds  
- Conduct **regular security training** for employees or users  
- Follow **NIST guidelines** for password and credential management  

---

### 📄 License  
MIT License — free to use, modify, and distribute with proper attribution.

---

**Author:** [Tarun167](https://github.com/Tarun167)  
**Repository:** [Personal-OSINT-Breach-Scanner](https://github.com/Tarun167/Personal-OSINT-Breach-Scanner)
