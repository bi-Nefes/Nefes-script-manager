/**
 * Hızlı Erişim JavaScript Dosyası
 * Favori yönetimi ve hızlı script çalıştırma özellikleri
 */

// Global değişkenler
let favoriteScripts = [];

// Sayfa yüklendiğinde çalışacak fonksiyonlar
document.addEventListener('DOMContentLoaded', function() {
    initializeQuickAccess();
    loadFavoriteScripts();
    setupToastNotifications();
});

/**
 * Hızlı erişim sistemini başlat
 */
function initializeQuickAccess() {
    console.log('🚀 Hızlı Erişim Sistemi başlatıldı');
    // Favori scriptleri yükle
    loadFavoriteScripts();
    // Toast container'ı oluştur
    createToastContainer();
}

/**
 * Favori scriptleri yükle
 */
function loadFavoriteScripts() {
    // Favori scriptleri localStorage'dan yükle
    const stored = localStorage.getItem('favoriteScripts');
    if (stored) {
        favoriteScripts = JSON.parse(stored);
    }
    // Favori scriptleri sunucudan da yükle
    fetch('/api/favorites')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                favoriteScripts = data.favorites;
                localStorage.setItem('favoriteScripts', JSON.stringify(favoriteScripts));
                updateFavoriteDisplay();
            }
        })
        .catch(error => {
            console.error('Favori scriptler yüklenirken hata:', error);
        });
}

/**
 * Hızlı çalıştırma modal'ını göster
 */
function showQuickRunModal() {
    fetch('/api/servers')
        .then(response => response.json())
        .then(servers => {
            if (servers.length === 0) {
                showToast('Önce sunucu eklemelisiniz!', 'error');
                return;
            }
            const modal = createQuickRunModal(servers);
            document.body.appendChild(modal);
            const modalInstance = new bootstrap.Modal(modal);
            modalInstance.show();
            modal.addEventListener('hidden.bs.modal', () => {
                document.body.removeChild(modal);
            });
        })
        .catch(error => {
            showToast('Sunucu listesi alınamadı!', 'error');
        });
}

/**
 * Hızlı çalıştırma modal'ını oluştur
 */
function createQuickRunModal(servers) {
    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.id = 'quickRunModal';
    modal.innerHTML = `
        <div class="modal-dialog modal-lg modal-dialog-centered custom-lower">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-bolt me-2"></i>Hızlı Script Çalıştır
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="row">
                        <div class="col-md-6">
                            <h6>Favori Scriptler</h6>
                            <div id="favorite-scripts-list">
                                ${favoriteScripts.length > 0 ? 
                                    favoriteScripts.map(script => `
                                        <div class="card mb-2">
                                            <div class="card-body p-2">
                                                <div class="d-flex justify-content-between align-items-center">
                                                    <div>
                                                        <strong>${script.name}</strong>
                                                        <br><small class="text-muted">${script.description || ''}</small>
                                                    </div>
                                                    <button class="btn btn-sm btn-primary" onclick="quickRunScript(${script.id})">
                                                        <i class="fas fa-play"></i>
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    `).join('') : 
                                    '<p class="text-muted">Henüz favori scriptiniz yok</p>'
                                }
                            </div>
                        </div>
                        <div class="col-md-6">
                            <h6>Sunucular</h6>
                            <div class="list-group">
                                ${servers.map(server => `
                                    <div class="list-group-item">
                                        <div class="d-flex justify-content-between align-items-center">
                                            <div>
                                                <strong>${server.name}</strong>
                                                <br><small class="text-muted">${server.host}</small>
                                            </div>
                                            <span class="badge bg-success">Aktif</span>
                                        </div>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Kapat</button>
                    <a href="/scripts" class="btn btn-primary">Tüm Scriptler</a>
                </div>
            </div>
        </div>
    `;
    return modal;
}

/**
 * Script'i hızlı çalıştır
 */
function quickRunScript(scriptId) {
    fetch(`/api/servers`)
        .then(response => response.json())
        .then(servers => {
            if (servers.length === 0) {
                showToast('Önce sunucu eklemelisiniz!', 'error');
                return;
            }
            if (servers.length === 1) {
                executeQuickRun(scriptId, servers[0].id);
            } else {
                showServerSelectionModal(scriptId, servers);
            }
        })
        .catch(error => {
            showToast('Sunucu listesi alınamadı!', 'error');
    });
}

/**
 * Toast bildirimlerini ayarla
 */
function setupToastNotifications() {
    // Toast container zaten oluşturulmuş olabilir
    if (!document.querySelector('.toast-container')) {
        createToastContainer();
    }
}

/**
 * Toast container oluştur
 */
function createToastContainer() {
    const container = document.createElement('div');
    container.className = 'toast-container position-fixed top-0 end-0 p-3';
    container.style.zIndex = '9999';
    document.body.appendChild(container);
    return container;
}

/**
 * Toast bildirimi göster
 */
function showToast(message, type = 'info', duration = 3000) {
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type} border-0`;
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                <i class="fas fa-${getToastIcon(type)} me-2"></i>${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    
    const container = document.querySelector('.toast-container') || createToastContainer();
    container.appendChild(toast);
    const toastInstance = new bootstrap.Toast(toast, { delay: duration });
    toastInstance.show();
    
    toast.addEventListener('hidden.bs.toast', () => {
        if (container.contains(toast)) {
            container.removeChild(toast);
        }
    });
}

/**
 * Toast icon'unu al
 */
function getToastIcon(type) {
    const icons = {
        'success': 'check',
        'error': 'exclamation-triangle',
        'warning': 'exclamation-circle',
        'info': 'info-circle'
    };
    return icons[type] || 'info-circle';
}

/**
 * Favori display'ini güncelle
 */
function updateFavoriteDisplay() {
    // Dashboard'daki favori bölümünü güncelle
    const favoritesSection = document.getElementById('favorites-section');
    if (favoritesSection) {
        // Favori scriptleri yeniden yükle
        location.reload();
    }
}

// Global fonksiyonları dışa aktar
window.quickAccess = {
    showToast,
    quickRunScript,
    loadFavoriteScripts,
    updateFavoriteDisplay
}; 