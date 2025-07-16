// script_scanner.js
// Pemindai keamanan untuk mendeteksi perilaku mencurigakan dalam file .txt berisi kode JavaScript atau Python

const fs = require('fs');
const path = require('path');

const suspiciousPatterns = [
  { lang: 'js', pattern: /private[_]?key\s*=\s*['"][a-zA-Z0-9]{32,}['"]/, reason: 'Private key tersimpan secara hardcoded (JS)' },
  { lang: 'js', pattern: /fetch\(.*['"]http:\/\/.+['"]/, reason: 'Permintaan HTTP keluar menggunakan fetch (JS)' },
  { lang: 'js', pattern: /axios\.(post|get)\(.*['"]http:\/\/.+['"]/, reason: 'Permintaan HTTP keluar menggunakan axios (JS)' },
  { lang: 'js', pattern: /eval\(/, reason: 'Penggunaan eval() (JS)' },
  { lang: 'js', pattern: /Function\(['"`]/, reason: 'Penggunaan konstruktor Function (JS)' },
  { lang: 'js', pattern: /new Wallet\(([^)]+)\)/, reason: 'Membuat wallet dengan input raw private key (JS)' },
  { lang: 'js', pattern: /sendTransaction\(.*privateKey/, reason: 'Transaksi dengan private key langsung (JS)' },

  { lang: 'py', pattern: /['"]?private_key['"]?\s*=\s*['"][a-zA-Z0-9]{32,}['"]/, reason: 'Private key tersimpan secara hardcoded (Python)' },
  { lang: 'py', pattern: /requests\.(post|get)\(.*['"]http:\/\/.+['"]/, reason: 'Permintaan HTTP keluar menggunakan requests (Python)' },
  { lang: 'py', pattern: /eval\(.+\)/, reason: 'Penggunaan eval() (Python)' },
  { lang: 'py', pattern: /exec\(.+\)/, reason: 'Penggunaan exec() (Python)' },
  { lang: 'py', pattern: /from web3 import Web3/, reason: 'Penggunaan modul Web3 untuk blockchain interaction (Python)' },
  { lang: 'py', pattern: /Web3\(.+\).eth.account.privateKeyToAccount/, reason: 'Konversi private key ke akun secara langsung (Python)' }
];

function detectLanguage(code) {
  if (code.includes('function') || code.includes('const') || code.includes('require')) return 'js';
  if (code.includes('import') || code.includes('def ') || code.includes('requests.')) return 'py';
  return 'unknown';
}

function scanFile(filePath) {
  const code = fs.readFileSync(filePath, 'utf8');
  const language = detectLanguage(code);
  const matches = suspiciousPatterns.filter(p => p.lang === language && p.pattern.test(code));

  const riskScore = Math.min((matches.length / 6) * 100, 100); 
  return {
    file: path.basename(filePath),
    bahasa: language.toUpperCase(),
    aman: matches.length === 0,
    risikoPersen: riskScore,
    peringatan: matches.map(m => m.reason)
  };
}

function scanFolder(folderPath) {
  const results = [];
  const files = fs.readdirSync(folderPath).filter(f => f.endsWith('.txt'));
  if (files.length === 0) return console.log('⚠️ Tidak ada file .txt ditemukan di folder:', folderPath);

  for (const file of files) {
    const fullPath = path.join(folderPath, file);
    const result = scanFile(fullPath);
    results.push(result);
  }

  const reportPath = path.join(__dirname, 'laporan_pemindaian.json');
  fs.writeFileSync(reportPath, JSON.stringify(results, null, 2));

  console.log(`\n✅ Pemindaian selesai. Laporan disimpan di: ${reportPath}\n`);
  for (const res of results) {
    console.log(`📄 ${res.file} | Bahasa: ${res.bahasa} | Aman: ${res.aman ? '✅' : '❌'} | Risiko: ${res.risikoPersen.toFixed(1)}%`);
    if (!res.aman) {
      res.peringatan.forEach(p => console.log(`   ⚠️  ${p}`));
    }
    console.log();
  }
}

const folderToScan = path.join(__dirname, 'scripts');
if (!fs.existsSync(folderToScan)) fs.mkdirSync(folderToScan);
console.log('🔍 Memindai folder:', folderToScan);
scanFolder(folderToScan);
