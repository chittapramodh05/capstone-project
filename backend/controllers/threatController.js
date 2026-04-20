const multer = require("multer");
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const FormData = require("form-data");

// Ensure upload directory exists
const uploadDir = path.join(__dirname, "../uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer Storage Configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + "-" + file.originalname);
  },
});

// Multer Upload Configuration (up to 200MB)
const upload = multer({
  storage: storage,
  limits: { fileSize: 200 * 1024 * 1024 },
});

exports.uploadMiddleware = upload.single("file");

exports.uploadFile = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: "No file uploaded. Please strictly provide a CSV." });
    }

    // Prepare form data for FastAPI ML microservice
    const form = new FormData();
    form.append('file', fs.createReadStream(req.file.path), {
      filename: req.file.originalname,
      contentType: req.file.mimetype,
    });

    try {
      // Forward to ML Backend (using host.docker.internal for Docker compatibility)
      const mlResponse = await axios.post("http://host.docker.internal:8000/analyze", form, {
        headers: {
          ...form.getHeaders()
        },
        maxContentLength: Infinity,
        maxBodyLength: Infinity
      });

      // Cleanup local file after successful transfer
      if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);

      res.status(200).json(mlResponse.data);

    } catch (mlErr) {
      console.error("ML API Error:", mlErr.message || mlErr);
      if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      return res.status(502).json({ message: "ML Pipeline analysis failed or timed out." });
    }

  } catch (err) {
    console.error("UPLOAD CONTROLLER ERROR:", err);
    res.status(500).json({ message: "Internal server error during upload." });
  }
};