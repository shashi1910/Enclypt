document.addEventListener("DOMContentLoaded", function () {
  // File upload handling
  const fileInput = document.getElementById("file-input");
  const fileInputDecrypt = document.getElementById("file-input-decrypt");
  const fileName = document.getElementById("file-name");
  const fileNameDecrypt = document.getElementById("file-name-decrypt");
  const dropArea = document.getElementById("drop-area");
  const dropAreaDecrypt = document.getElementById("drop-area-decrypt");

  // Handle file selection for encryption
  if (fileInput && fileName && dropArea) {
    fileInput.addEventListener("change", function () {
      if (this.files.length > 0) {
        fileName.textContent = this.files[0].name;
        dropArea.classList.add("highlight");
      } else {
        fileName.textContent = "Choose a file or drag it here";
        dropArea.classList.remove("highlight");
      }
    });

    // Drag and drop functionality
    ["dragenter", "dragover", "dragleave", "drop"].forEach((eventName) => {
      dropArea.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
      e.preventDefault();
      e.stopPropagation();
    }

    ["dragenter", "dragover"].forEach((eventName) => {
      dropArea.addEventListener(eventName, highlight, false);
    });

    ["dragleave", "drop"].forEach((eventName) => {
      dropArea.addEventListener(eventName, unhighlight, false);
    });

    function highlight() {
      dropArea.classList.add("highlight");
    }

    function unhighlight() {
      dropArea.classList.remove("highlight");
    }

    dropArea.addEventListener("drop", handleDrop, false);

    function handleDrop(e) {
      const dt = e.dataTransfer;
      const files = dt.files;

      if (files.length > 0) {
        fileInput.files = files;
        fileName.textContent = files[0].name;
      }
    }
  }

  // Handle file selection for decryption
  if (fileInputDecrypt && fileNameDecrypt && dropAreaDecrypt) {
    fileInputDecrypt.addEventListener("change", function () {
      if (this.files.length > 0) {
        fileNameDecrypt.textContent = this.files[0].name;
        dropAreaDecrypt.classList.add("highlight");
      } else {
        fileNameDecrypt.textContent = "Choose an encrypted file (.enc)";
        dropAreaDecrypt.classList.remove("highlight");
      }
    });

    // Similar drag and drop functionality for decryption
    ["dragenter", "dragover", "dragleave", "drop"].forEach((eventName) => {
      dropAreaDecrypt.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
      e.preventDefault();
      e.stopPropagation();
    }

    ["dragenter", "dragover"].forEach((eventName) => {
      dropAreaDecrypt.addEventListener(
        eventName,
        function () {
          dropAreaDecrypt.classList.add("highlight");
        },
        false
      );
    });

    ["dragleave", "drop"].forEach((eventName) => {
      dropAreaDecrypt.addEventListener(
        eventName,
        function () {
          dropAreaDecrypt.classList.remove("highlight");
        },
        false
      );
    });

    dropAreaDecrypt.addEventListener(
      "drop",
      function (e) {
        const dt = e.dataTransfer;
        const files = dt.files;

        if (files.length > 0) {
          fileInputDecrypt.files = files;
          fileNameDecrypt.textContent = files[0].name;
        }
      },
      false
    );
  }

  // Copy key to clipboard
  window.copyToClipboard = function (elementId) {
    const element = document.getElementById(elementId);
    const text = element.textContent;

    navigator.clipboard.writeText(text).then(
      function () {
        // Success feedback
        const copyBtn = document.getElementById("copy-key-btn");
        const originalText = copyBtn.innerHTML;
        copyBtn.innerHTML = '<i class="fas fa-check"></i> Copied!';

        setTimeout(function () {
          copyBtn.innerHTML = originalText;
        }, 2000);
      },
      function (err) {
        console.error("Could not copy text: ", err);
      }
    );
  };

  // Auto-dismiss alerts after 5 seconds
  const alerts = document.querySelectorAll(".alert");
  alerts.forEach((alert) => {
    setTimeout(() => {
      alert.style.display = "none";
    }, 5000);
  });
});
