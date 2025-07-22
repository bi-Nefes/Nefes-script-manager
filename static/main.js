// Şifre göster/gizle fonksiyonu (login.html içinde de inline var, burada genel olarak kullanılabilir)
function togglePasswordField(id) {
  const pwd = document.getElementById(id);
  if (pwd.type === 'password') {
    pwd.type = 'text';
  } else {
    pwd.type = 'password';
  }
}

// Terminal Loading Animation
function showTerminalLoading(pageName = 'Sayfa') {
  const terminalMessages = [
    "> NSM NEFES SCRIPT MANAGER başlatılıyor...",
    "> SSH bağlantıları kontrol ediliyor...",
    "> Script veritabanı yükleniyor...",
    "> Kullanıcı yetkileri doğrulanıyor...",
    `> ${pageName} hazırlanıyor...`,
    "> Tamamlandı! ✓"
  ];
  
  const terminalContainer = document.createElement('div');
  terminalContainer.className = 'terminal-container';
  terminalContainer.innerHTML = `
    <div class="terminal-header">
      <i class="fas fa-terminal me-2"></i>NSM NEFES SCRIPT MANAGER
    </div>
    <div id="terminal-messages"></div>
  `;
  
  document.body.appendChild(terminalContainer);
  
  const messagesContainer = document.getElementById('terminal-messages');
  let currentIndex = 0;
  
  function addMessage() {
    if (currentIndex < terminalMessages.length) {
      const messageDiv = document.createElement('div');
      messageDiv.className = 'terminal-line';
      messageDiv.textContent = terminalMessages[currentIndex];
      messagesContainer.appendChild(messageDiv);
      currentIndex++;
      
      setTimeout(addMessage, 300);
    } else {
      // Animasyon bitti, terminal'i kaldır
      setTimeout(() => {
        terminalContainer.style.opacity = '0';
        terminalContainer.style.transition = 'opacity 0.5s ease-out';
        setTimeout(() => {
          if (document.body.contains(terminalContainer)) {
            document.body.removeChild(terminalContainer);
          }
        }, 500);
      }, 500);
    }
  }
  
  addMessage();
}

// Sayfa geçişlerinde terminal animasyonu
document.addEventListener('DOMContentLoaded', function() {
  // Link tıklamalarını yakala
  document.addEventListener('click', function(e) {
    if (e.target.tagName === 'A' && e.target.href && !e.target.href.includes('#')) {
      const link = e.target.href;
      const currentPage = window.location.pathname;
      
      // Aynı sayfaya gitmiyorsa animasyon göster
      if (link !== currentPage && !link.includes('logout')) {
        e.preventDefault();
        showTerminalLoading(getPageName(link));
        
        setTimeout(() => {
          window.location.href = link;
        }, 2000); // 2 saniye sonra sayfaya git
      }
    }
  });
});

// Sayfa adını al
function getPageName(url) {
  const pageNames = {
    '/': 'Ana Sayfa',
    '/servers': 'Sunucular',
    '/scripts': 'Scriptler',
    '/run': 'Script Çalıştır',
    '/scheduler': 'Zamanlayıcı',
    '/logs': 'Kayıtlar',
    '/users': 'Kullanıcılar'
  };
  
  const path = new URL(url).pathname;
  return pageNames[path] || 'Sayfa';
}

// Basit form doğrulama (örnek)
document.addEventListener('DOMContentLoaded', function() {
  const forms = document.querySelectorAll('form[novalidate]');
  Array.from(forms).forEach(function(form) {
    form.addEventListener('submit', function(event) {
      if (!form.checkValidity()) {
        event.preventDefault();
        event.stopPropagation();
        form.classList.add('was-validated');
      }
    }, false);
  });
}); 