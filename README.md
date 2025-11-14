# 🔐 Blowfish Algorithm Visualizer

An interactive Streamlit-based web application to visualize and understand how the Blowfish symmetric-key encryption algorithm works.

🚀 **Live Demo:**  
https://blowfish-visualizer.streamlit.app/

📘 **Presentation (Working of Blowfish Algorithm):**  
https://www.canva.com/design/DAG4TGp9r1A/vTWP5i4YAIItUc1OCtPD6A/view

---

## 📖 Overview

The **Blowfish Algorithm Visualizer** helps users deeply understand the internal workflow of the Blowfish cipher.  
It visualizes:

- Key expansion  
- Feistel network structure  
- Sixteen encryption rounds  
- S-box and P-array transformations  
- Step-by-step encryption & decryption flow  

Designed for **students, cybersecurity learners, and developers**, this tool makes cryptography easier to grasp.

---

## ✨ Features

### 🔍 Interactive Visualizations
- Real-time step-by-step encryption flow  
- Round-by-round Feistel network breakdown  
- L (left) and R (right) half transformations  
- Visual P-array and S-box lookups  

### 🔐 Encryption & Decryption
- Encrypt custom plaintext using a user-defined key  
- Decrypt ciphertext back to plaintext  
- Understand all 16 internal rounds of Blowfish  

### 🧠 Educational Value
- Shows confusion & diffusion principles  
- Demonstrates how subkeys and S-boxes influence the cipher  
- Ideal for academic or demonstration purposes  

### 🌐 Web-Based
- No installation required  
- Built with **Python + Streamlit**

---

## 🛠️ Tech Stack

- Python 3.x  
- Streamlit  
- NumPy  
- Custom Blowfish implementation

---

## ▶️ Run Locally

```bash
# Clone the repository
git clone https://github.com/Ravi-Teja-S/Blowfish_Visualizer.git
cd blowfish-visualizer

# Install required packages
pip install -r requirements.txt

# Run the app
streamlit run visualizer.py


