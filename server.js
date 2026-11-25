const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3050;
const JWT_SECRET = process.env.JWT_SECRET || "ganti-dengan-string-acak-panjang-untuk-produksi-2026";

app.use(express.json({ limit: "15mb" }));
app.use(express.static(path.join(__dirname, "public")));

const db = new Database(path.join(__dirname, "asas.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    nama TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    salt_kunci TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS paket_soal (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    mapel TEXT NOT NULL,
    nama_paket TEXT NOT NULL,
    jenjang TEXT NOT NULL,
    aturan_mcma TEXT NOT NULL,
    offset_top INTEGER DEFAULT 52,
    encrypted_soal TEXT NOT NULL,
    iv TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS hasil_koreksi (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    paket_id TEXT NOT NULL,
    nama_siswa TEXT NOT NULL,
    kelas TEXT NOT NULL,
    nilai_akhir REAL NOT NULL,
    status_validasi TEXT NOT NULL,
    ringkasan_cetak TEXT NOT NULL,
    raw_jawaban_json TEXT NOT NULL,
    skor_per_soal_json TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (paket_id) REFERENCES paket_soal(id) ON DELETE CASCADE
  );
`);

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Sesi berakhir, silakan login ulang." });
  const token = authHeader.split(" ")[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: "Token tidak valid atau kedaluwarsa." });
  }
}

app.post("/api/auth/register", (req, res) => {
  const { nama, email, password } = req.body;
  if (!nama || !email || !password) {
    return res.status(400).json({ error: "Lengkapi nama, email, dan password." });
  }

  try {
    const passwordHash = bcrypt.hashSync(password, 10);
    const saltKunci = crypto.randomBytes(16).toString("hex");
    const emailClean = email.toLowerCase().trim();
    const namaClean = nama.trim();

    const info = db
      .prepare("INSERT INTO users (email, nama, password_hash, salt_kunci) VALUES (?, ?, ?, ?)")
      .run(emailClean, namaClean, passwordHash, saltKunci);

    const token = jwt.sign(
      { id: info.lastInsertRowid, email: emailClean, nama: namaClean },
      JWT_SECRET,
      { expiresIn: "7d" }
    );
    res.json({ token, user: { nama: namaClean, email: emailClean, saltKunci } });
  } catch (e) {
    res.status(400).json({ error: "Email sudah terdaftar. Silakan login." });
  }
});

app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body;
  const user = db
    .prepare("SELECT * FROM users WHERE email = ?")
    .get((email || "").toLowerCase().trim());

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: "Email atau password salah." });
  }

  const token = jwt.sign(
    { id: user.id, email: user.email, nama: user.nama },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
  res.json({ token, user: { nama: user.nama, email: user.email, saltKunci: user.salt_kunci } });
});

app.get("/api/paket", authMiddleware, (req, res) => {
  const rows = db
    .prepare("SELECT * FROM paket_soal WHERE user_id = ? ORDER BY updated_at DESC")
    .all(req.user.id);
  res.json(rows);
});

app.post("/api/paket", authMiddleware, (req, res) => {
  const { id, mapel, namaPaket, jenjang, aturanMcma, offsetTop, encryptedSoal, iv } = req.body;
  if (!mapel || !namaPaket || !encryptedSoal || !iv) {
    return res.status(400).json({ error: "Data paket tidak lengkap." });
  }

  const paketId = id || "PKT-" + Date.now();
  const existing = db
    .prepare("SELECT id FROM paket_soal WHERE id = ? AND user_id = ?")
    .get(paketId, req.user.id);

  if (existing) {
    db.prepare(`
      UPDATE paket_soal
      SET mapel = ?, nama_paket = ?, jenjang = ?, aturan_mcma = ?, offset_top = ?, encrypted_soal = ?, iv = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ? AND user_id = ?
    `).run(
      mapel.trim(),
      namaPaket.trim(),
      jenjang,
      aturanMcma,
      offsetTop || 52,
      encryptedSoal,
      iv,
      paketId,
      req.user.id
    );
  } else {
    db.prepare(`
      INSERT INTO paket_soal (id, user_id, mapel, nama_paket, jenjang, aturan_mcma, offset_top, encrypted_soal, iv)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      paketId,
      req.user.id,
      mapel.trim(),
      namaPaket.trim(),
      jenjang,
      aturanMcma,
      offsetTop || 52,
      encryptedSoal,
      iv
    );
  }

  res.json({ status: "sukses", id: paketId });
});

app.delete("/api/paket/:id", authMiddleware, (req, res) => {
  const info = db
    .prepare("DELETE FROM paket_soal WHERE id = ? AND user_id = ?")
    .run(req.params.id, req.user.id);
  if (info.changes === 0) return res.status(404).json({ error: "Paket tidak ditemukan." });
  res.json({ status: "sukses" });
});

app.post("/api/ocr-proxy", authMiddleware, async (req, res) => {
  const { modeOcr, apiKey, base64Image, jenjang, jumlahSoal } = req.body;
  if (!apiKey) return res.status(400).json({ error: "API Key belum diisi pada Pengaturan Akun." });

  try {
    if (modeOcr === "GEMINI") {
      const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent?key=${apiKey}`;
      const hurufValid = jenjang === "SMA" ? "A, B, C, D, atau E" : "A, B, C, atau D";
      const propsSoal = {};
      for (let i = 1; i <= jumlahSoal; i++) propsSoal["no_" + i] = { type: "STRING" };

      const payload = {
        contents: [
          {
            parts: [
              { inlineData: { mimeType: "image/jpeg", data: base64Image } },
              {
                text: `Ekstrak data dari foto lembar jawaban ujian ini. Baca nama siswa dan kelas pada bagian atas. Untuk nomor 1 sampai ${jumlahSoal}, baca huruf opsi (${hurufValid}) yang disilang, dicentang, atau dilingkari. Jika lebih dari satu huruf dipilih pada nomor yang sama, gabungkan dengan koma (contoh: "A, C"). Jika kosong, isi "".`
              }
            ]
          }
        ],
        generationConfig: {
          responseMimeType: "application/json",
          responseSchema: {
            type: "OBJECT",
            properties: {
              identitas: {
                type: "OBJECT",
                properties: {
                  nama_siswa: { type: "STRING" },
                  kelas: { type: "STRING" }
                },
                required: ["nama_siswa", "kelas"]
              },
              jawaban_pg: { type: "OBJECT", properties: propsSoal }
            },
            required: ["identitas", "jawaban_pg"]
          }
        }
      };

      const fetchRes = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      if (!fetchRes.ok) {
        return res.status(400).json({ error: "Gagal memanggil Gemini API. Periksa kuota atau API Key Anda." });
      }
      const data = await fetchRes.json();
      const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
      return res.json(JSON.parse(text));
    } else {
      const hurufValid = jenjang === "SMA" ? "A-E" : "A-D";
      const regexPola = `^[${hurufValid}](,\\s*[${hurufValid}])*$`;
      const propsSoal = {};
      for (let i = 1; i <= jumlahSoal; i++) {
        propsSoal["no_" + i] = { type: "string", pattern: regexPola };
      }

      const schema = {
        type: "object",
        properties: {
          identitas: {
            type: "object",
            properties: {
              nama_siswa: { type: "string" },
              kelas: { type: "string" }
            },
            required: ["nama_siswa", "kelas"]
          },
          jawaban_pg: { type: "object", properties: propsSoal }
        },
        required: ["identitas", "jawaban_pg"]
      };

      const formData = new FormData();
      const imgBuffer = Buffer.from(base64Image, "base64");
      formData.append("file", new Blob([imgBuffer], { type: "image/jpeg" }), "lembar.jpg");
      formData.append("schema", JSON.stringify(schema));

      const fetchRes = await fetch("https://api.snaptojson.com/partner/v1/snaps", {
        method: "POST",
        headers: { Authorization: "Bearer " + apiKey },
        body: formData
      });
      if (!fetchRes.ok) return res.status(400).json({ error: "Foto gagal dibaca oleh snaptojson." });
      return res.json(await fetchRes.json());
    }
  } catch (err) {
    res.status(500).json({ error: "Kesalahan jaringan saat membaca dokumen: " + err.message });
  }
});

app.post("/api/hasil", authMiddleware, (req, res) => {
  const {
    paketId,
    namaSiswa,
    kelas,
    nilaiAkhir,
    statusValidasi,
    ringkasanCetak,
    rawJawaban,
    skorPerSoal
  } = req.body;

  const info = db
    .prepare(`
      INSERT INTO hasil_koreksi (user_id, paket_id, nama_siswa, kelas, nilai_akhir, status_validasi, ringkasan_cetak, raw_jawaban_json, skor_per_soal_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    .run(
      req.user.id,
      paketId,
      namaSiswa,
      kelas,
      nilaiAkhir,
      statusValidasi,
      ringkasanCetak,
      JSON.stringify(rawJawaban),
      JSON.stringify(skorPerSoal)
    );

  res.json({ status: "sukses", id: info.lastInsertRowid });
});

app.delete("/api/hasil/:id", authMiddleware, (req, res) => {
  const info = db
    .prepare("DELETE FROM hasil_koreksi WHERE id = ? AND user_id = ?")
    .run(req.params.id, req.user.id);
  if (info.changes === 0) return res.status(404).json({ error: "Data hasil tidak ditemukan." });
  res.json({ status: "sukses" });
});

app.get("/api/hasil/paket/:paketId", authMiddleware, (req, res) => {
  const rows = db
    .prepare("SELECT * FROM hasil_koreksi WHERE user_id = ? AND paket_id = ? ORDER BY id ASC")
    .all(req.user.id, req.params.paketId);
  res.json(rows);
});

app.get("/api/hasil/mapel/:mapel", authMiddleware, (req, res) => {
  const rows = db
    .prepare(`
      SELECT h.*, p.nama_paket, p.jenjang
      FROM hasil_koreksi h
      JOIN paket_soal p ON h.paket_id = p.id
      WHERE h.user_id = ? AND LOWER(p.mapel) = LOWER(?)
      ORDER BY h.kelas ASC, h.nama_siswa ASC
    `)
    .all(req.user.id, req.params.mapel);
  res.json(rows);
});

app.listen(PORT, () => {
  console.log(`Smart ASAS v3 berjalan di http://localhost:${PORT}`);
});
