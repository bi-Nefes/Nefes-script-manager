// Script Çıktısı Gelişmiş Fonksiyonları

// Panoya kopyalama
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    const text = element.textContent || element.innerText;
    
    navigator.clipboard.writeText(text).then(function() {
        showToast('Çıktı panoya kopyalandı!', 'success');
    }).catch(function(err) {
        console.error('Kopyalama hatası:', err);
        showToast('Kopyalama başarısız!', 'error');
    });
}

// Çıktıyı indirme
function downloadOutput(logId, scriptName, timestamp) {
    const element = document.getElementById('output-' + logId);
    const text = element.textContent || element.innerText;
    
    const blob = new Blob([text], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${scriptName}_${timestamp}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
    
    showToast('Çıktı indirildi!', 'success');
}

// Kelime kaydırma toggle
function toggleWordWrap(elementId) {
    const element = document.getElementById(elementId);
    const currentStyle = element.style.whiteSpace;
    
    if (currentStyle === 'pre-wrap') {
        element.style.whiteSpace = 'pre';
        element.style.wordWrap = 'normal';
        showToast('Kelime kaydırma kapatıldı', 'info');
    } else {
        element.style.whiteSpace = 'pre-wrap';
        element.style.wordWrap = 'break-word';
        showToast('Kelime kaydırma açıldı', 'info');
    }
}

// Satır numaraları toggle
function toggleLineNumbers(elementId) {
    const element = document.getElementById(elementId);
    const hasLineNumbers = element.classList.contains('line-numbers');
    
    if (hasLineNumbers) {
        element.classList.remove('line-numbers');
        element.innerHTML = element.innerHTML.replace(/^\d+:\s/gm, '');
        showToast('Satır numaraları kaldırıldı', 'info');
    } else {
        element.classList.add('line-numbers');
        const lines = element.innerHTML.split('\n');
        const numberedLines = lines.map((line, index) => `${index + 1}: ${line}`).join('\n');
        element.innerHTML = numberedLines;
        showToast('Satır numaraları eklendi', 'info');
    }
}

// Çıktıda arama
function searchInOutput(elementId) {
    const searchDiv = document.getElementById('search-' + elementId.replace('output-', ''));
    const isVisible = searchDiv.style.display !== 'none';
    
    if (isVisible) {
        searchDiv.style.display = 'none';
        clearHighlight(elementId);
    } else {
        searchDiv.style.display = 'block';
        searchDiv.querySelector('input').focus();
    }
}

// Arama vurgulama
function highlightSearch(elementId, searchText) {
    const element = document.getElementById(elementId);
    const text = element.textContent || element.innerText;
    
    if (!searchText) {
        element.innerHTML = text;
        return;
    }
    
    const regex = new RegExp(`(${searchText})`, 'gi');
    const highlightedText = text.replace(regex, '<mark class="bg-warning text-dark">$1</mark>');
    element.innerHTML = highlightedText;
}

// Vurgulamayı temizle
function clearHighlight(elementId) {
    const element = document.getElementById(elementId);
    const text = element.textContent || element.innerText;
    element.innerHTML = text;
}

// Toast mesajı göster
function showToast(message, type = 'info') {
    // Bootstrap toast varsa kullan, yoksa alert
    if (typeof bootstrap !== 'undefined' && bootstrap.Toast) {
        const toastHtml = `
            <div class="toast align-items-center text-white bg-${type === 'success' ? 'success' : type === 'error' ? 'danger' : 'info'} border-0" role="alert" aria-live="assertive" aria-atomic="true">
                <div class="d-flex">
                    <div class="toast-body">
                        ${message}
                    </div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
                </div>
            </div>
        `;
        
        const toastContainer = document.getElementById('toast-container') || createToastContainer();
        toastContainer.insertAdjacentHTML('beforeend', toastHtml);
        
        const toastElement = toastContainer.lastElementChild;
        const toast = new bootstrap.Toast(toastElement);
        toast.show();
        
        // Toast'ı otomatik kaldır
        setTimeout(() => {
            toastElement.remove();
        }, 3000);
    } else {
        alert(message);
    }
}

// Toast container oluştur
function createToastContainer() {
    const container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container position-fixed top-0 end-0 p-3';
    container.style.zIndex = '9999';
    document.body.appendChild(container);
    return container;
}

// Sayfa yüklendiğinde çalışacak fonksiyonlar
document.addEventListener('DOMContentLoaded', function() {
    // Çıktı alanlarına syntax highlighting ekle
    const outputElements = document.querySelectorAll('pre[id^="output-"]');
    outputElements.forEach(element => {
        // Uzun çıktılar için "daha fazla göster" butonu
        if (element.textContent.length > 1000) {
            const showMoreBtn = document.createElement('button');
            showMoreBtn.className = 'btn btn-sm btn-outline-light mt-2';
            showMoreBtn.innerHTML = '<i class="fas fa-chevron-down me-1"></i>Daha Fazla Göster';
            showMoreBtn.onclick = function() {
                element.style.maxHeight = 'none';
                this.style.display = 'none';
            };
            element.parentNode.appendChild(showMoreBtn);
        }
    });
}); 