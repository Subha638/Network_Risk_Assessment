# AI Network Risk Assessment — Sidebar + OCR Bridge Fix

## Run on Windows / VS Code
1. Extract this ZIP and open the extracted `fixed_project` folder in VS Code.
2. In terminal:
   ```powershell
   py -m venv .venv
   .venv\Scripts\activate
   python -m pip install -r requirements.txt
   python app.py
   ```
3. Open http://127.0.0.1:5000
4. Admin login: `admin` / `admin123`. Guest login: `guest` / `guest123`.
5. Sidebar navigation is available to Admin. Guest only has the Guest Security Test page.

## OCR bridge
Keep Flask running. In a second terminal, activate `.venv` and run:
`python packet_tracer_bridge.py`
Keep Packet Tracer visible with a completed `ping -n 4 <target-ip>` output. OCR checks the visible screen every 3 seconds; keep the ping command and result visible. OCR can misread text, so verify imported events.

If Tesseract is not found automatically, edit `packet_tracer_bridge.py` and set `pytesseract.pytesseract.tesseract_cmd` to the full path of `tesseract.exe`.

The dashboard's browser policy tests are demonstrations; Packet Tracer remains the network simulator. The OCR bridge reads visible screen output and posts interpreted test events to Flask.
