# 📥 How to Install Corsair Unbound

Corsair Unbound is not yet on the Chrome Web Store. Installation is manual but takes less than 60 seconds.

## Step 1 — Download the extension

1. Go to the [Releases page](https://github.com/amiraction0938/Corsair-Unbound/releases)
2. Find the latest release (at the top of the list)
3. Under **Assets**, click **`corsair-unbound-extension.zip`**
4. The file will download to your Downloads folder

## Step 2 — Extract the ZIP

1. Find the downloaded ZIP in your Downloads folder
2. Right-click → **Extract All…**
3. Choose a **permanent** location (e.g. `Documents/Corsair-Unbound`)

   > ⚠️ Do NOT delete this folder later — Chrome loads the extension from it every time you open the browser.

4. Click **Extract**

## Step 3 — Load in Chrome

1. Open a new tab and go to `chrome://extensions`
2. Turn on **Developer mode** (toggle in the top-right corner)
3. Click **Load unpacked** (top-left)
4. Select the folder you extracted in Step 2 (the one containing `manifest.json`)
5. Done! You should see the Corsair Unbound icon in your toolbar

## Step 4 — First-time setup

1. Click the Corsair Unbound icon in the toolbar
2. Click **Open Dashboard**
3. Go to **API & Intelligence** and paste your free VirusTotal API key
   ([get one here](https://www.virustotal.com/gui/my-apikey))
4. Enable **VirusTotal Threat Intelligence** and **Auto-Scan**
5. (Optional) Pick your language from the sidebar

## Updating to a new version

1. Download the new release ZIP (Step 1)
2. Extract it, overwriting the existing folder (Step 2)
3. Go to `chrome://extensions` and click the **↻ reload** button on the Corsair Unbound card

Your settings, profiles, blocklists, and cache are **preserved** — they live in Chrome's storage, not in the extension files.

## Uninstalling

1. Go to `chrome://extensions`
2. Click **Remove** on the Corsair Unbound card
3. (Optional) Delete the extracted folder from Step 2

## Troubleshooting

**"Manifest file is missing or unreadable"**
- You selected the wrong folder. Make sure `manifest.json` is directly inside the folder you selected.

**The extension icon doesn't appear**
- Click the puzzle-piece icon in Chrome's toolbar and pin Corsair Unbound.

**Threat intelligence shows "Not configured"**
- You need a free VirusTotal API key. See Step 4.