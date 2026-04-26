/**
 * ObjectPicker — tag-based multi-select with live search
 *
 * Usage:
 *   const p = new ObjectPicker(containerEl, {
 *     items: [{id, name, global}],
 *     placeholder: 'Search...',
 *     tagClass: ''          // extra CSS class on tags (e.g. 'zone-t' or 'svc-t')
 *   });
 *   p.setItems(newItems);   // replace items
 *   p.getSelected();        // → [{id, name}]
 *   p.getSelectedIds();     // → [id, ...]
 *   p.clear();
 */
class ObjectPicker {
    constructor(container, options = {}) {
        this.container = container;
        this.allItems = options.items || [];
        this.selected = [];
        this.placeholder = options.placeholder || 'Search objects...';
        this.tagClass = options.tagClass || '';
        this.onCreateNew = options.onCreateNew || null;
        this._build();
    }

    _build() {
        this.container.className = 'picker-wrap';
        this.container.innerHTML = `
            <div class="picker-tags" id="${this._id('tags')}">
                <input class="picker-input" id="${this._id('inp')}" placeholder="${this.placeholder}" autocomplete="off" spellcheck="false">
            </div>
            <div class="picker-dropdown" id="${this._id('dd')}"></div>
        `;
        this.tagsEl = this.container.querySelector(`#${this._id('tags')}`);
        this.inputEl = this.container.querySelector(`#${this._id('inp')}`);
        this.ddEl = this.container.querySelector(`#${this._id('dd')}`);

        this.inputEl.addEventListener('input', () => this._renderDropdown());
        this.inputEl.addEventListener('focus', () => this._openDropdown());
        this.inputEl.addEventListener('keydown', (e) => this._onKey(e));

        document.addEventListener('click', (e) => {
            if (!this.container.contains(e.target)) this._closeDropdown();
        });
    }

    _id(suffix) {
        if (!this._uid) this._uid = 'picker_' + Math.random().toString(36).slice(2, 8);
        return this._uid + '_' + suffix;
    }

    setItems(items) {
        this.allItems = items || [];
        if (this.ddEl.classList.contains('open')) this._renderDropdown();
    }

    getSelected() { return [...this.selected]; }
    getSelectedIds() { return this.selected.map(s => s.id); }

    clear() {
        this.selected = [];
        this._renderTags();
    }

    setSelectedByIds(ids) {
        if (!ids || !ids.length) { this.selected = []; this._renderTags(); return; }
        this.selected = ids.map(id => {
            const item = this.allItems.find(it => it.id === id);
            return { id, name: item ? item.name : id };
        });
        this._renderTags();
    }

    _openDropdown() {
        this._renderDropdown();
        this.ddEl.classList.add('open');
    }

    _closeDropdown() {
        this.ddEl.classList.remove('open');
    }

    _renderDropdown() {
        const q = this.inputEl.value.toLowerCase().trim();
        const selIds = new Set(this.selected.map(s => s.id));
        let visible = this.allItems.filter(it => {
            if (selIds.has(it.id)) return false;
            if (!q) return true;
            return it.name.toLowerCase().includes(q);
        });

        if (visible.length === 0) {
            this.ddEl.innerHTML = `<div class="picker-empty">${q ? 'No matches' : 'All objects selected or none available'}</div>`;
        } else {
            this.ddEl.innerHTML = visible.slice(0, 100).map(it => `
                <div class="picker-item" data-id="${it.id}" data-name="${this._esc(it.name)}">
                    ${it.global ? '<span class="global-badge">G</span>' : ''}
                    <span class="text-truncate">${this._highlight(it.name, q)}</span>
                </div>
            `).join('');
            if (visible.length > 100) {
                this.ddEl.innerHTML += `<div class="picker-empty">… ${visible.length - 100} more, refine search</div>`;
            }
            this.ddEl.querySelectorAll('.picker-item').forEach(el => {
                el.addEventListener('mousedown', (e) => {
                    e.preventDefault();
                    this._select(el.dataset.id, el.dataset.name);
                });
            });
        }

        // "Create new" option — shown when there is a search query and a callback is set
        if (this.onCreateNew && q) {
            const createEl = document.createElement('div');
            createEl.className = 'picker-create-item';
            createEl.innerHTML = `<i class="fas fa-plus-circle" style="flex-shrink:0"></i><span>Create <b>"${this._esc(q)}"</b></span>`;
            createEl.addEventListener('mousedown', (e) => {
                e.preventDefault();
                const query = q;
                this.inputEl.value = '';
                this._closeDropdown();
                this.onCreateNew(query, (item) => this.addItemAndSelect(item));
            });
            this.ddEl.appendChild(createEl);
        }

        this.ddEl.classList.add('open');
    }

    _select(id, name) {
        if (!this.selected.find(s => s.id === id)) {
            this.selected.push({ id, name });
            this._renderTags();
        }
        this.inputEl.value = '';
        this._renderDropdown();
        this.inputEl.focus();
    }

    addItemAndSelect(item) {
        if (!item || !item.id) return;
        if (!this.allItems.find(it => it.id === item.id)) {
            this.allItems.push(item);
        }
        this._select(item.id, item.name);
    }

    _deselect(id) {
        this.selected = this.selected.filter(s => s.id !== id);
        this._renderTags();
        this._renderDropdown();
    }

    _renderTags() {
        const inp = this.inputEl;
        this.tagsEl.innerHTML = '';
        this.selected.forEach(s => {
            const tag = document.createElement('span');
            tag.className = `picker-tag ${this.tagClass}`;
            tag.innerHTML = `<span class="text-truncate" title="${this._esc(s.name)}" style="max-width:150px">${this._esc(s.name)}</span><span class="picker-tag-rm" data-id="${s.id}">&times;</span>`;
            tag.querySelector('.picker-tag-rm').addEventListener('click', () => this._deselect(s.id));
            this.tagsEl.appendChild(tag);
        });
        this.tagsEl.appendChild(inp);
        inp.placeholder = this.selected.length ? '' : this.placeholder;
    }

    _onKey(e) {
        if (e.key === 'Backspace' && !this.inputEl.value && this.selected.length) {
            this._deselect(this.selected[this.selected.length - 1].id);
        }
        if (e.key === 'Escape') this._closeDropdown();
    }

    _highlight(name, q) {
        if (!q) return this._esc(name);
        const idx = name.toLowerCase().indexOf(q);
        if (idx === -1) return this._esc(name);
        return this._esc(name.slice(0, idx)) +
               '<mark style="background:#dbeafe;padding:0;border-radius:2px">' +
               this._esc(name.slice(idx, idx + q.length)) +
               '</mark>' +
               this._esc(name.slice(idx + q.length));
    }

    _esc(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }
}

/* ---- Toast helper ---- */
function showToast(msg, type = 'info', duration = 3500) {
    let stack = document.querySelector('.toast-stack');
    if (!stack) {
        stack = document.createElement('div');
        stack.className = 'toast-stack';
        document.body.appendChild(stack);
    }
    const icons = { info: 'fa-info-circle', success: 'fa-check-circle', error: 'fa-exclamation-circle', warning: 'fa-exclamation-triangle' };
    const t = document.createElement('div');
    t.className = `toast-msg ${type}`;
    t.innerHTML = `<i class="fas ${icons[type] || icons.info}"></i><span>${msg}</span>`;
    stack.appendChild(t);
    setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity .3s'; setTimeout(() => t.remove(), 300); }, duration);
}

/* ---- Loading overlay ---- */
function showLoading(msg = 'Processing…') {
    let el = document.getElementById('_loading_overlay');
    if (!el) {
        el = document.createElement('div');
        el.id = '_loading_overlay';
        el.className = 'loading-overlay';
        el.innerHTML = `<div class="spinner-ring"></div><div id="_loading_msg" style="font-size:14px;font-weight:600">${msg}</div>`;
        document.body.appendChild(el);
    } else {
        document.getElementById('_loading_msg').textContent = msg;
        el.classList.remove('hidden');
    }
}

function hideLoading() {
    const el = document.getElementById('_loading_overlay');
    if (el) el.classList.add('hidden');
}

/* ---- Simple confirm dialog ---- */
function confirmDialog(title, msg, okLabel = 'Confirm', dangerOk = true) {
    return new Promise((resolve) => {
        let el = document.getElementById('_confirm_dialog');
        if (!el) {
            el = document.createElement('div');
            el.id = '_confirm_dialog';
            el.innerHTML = `
                <div style="position:fixed;inset:0;background:rgba(15,23,42,.5);z-index:9100;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(2px)">
                    <div style="background:#fff;border-radius:12px;padding:24px;max-width:360px;width:90%;box-shadow:0 20px 40px rgba(0,0,0,.2)">
                        <div id="_cd_icon" class="confirm-icon"></div>
                        <h5 id="_cd_title" style="text-align:center;font-weight:700;margin-bottom:8px"></h5>
                        <p id="_cd_msg" style="text-align:center;color:#64748b;font-size:13px;margin-bottom:20px"></p>
                        <div style="display:flex;gap:8px">
                            <button id="_cd_cancel" style="flex:1;padding:8px;border:1px solid #e2e8f0;border-radius:8px;background:#fff;cursor:pointer;font-weight:600;font-size:13px">Cancel</button>
                            <button id="_cd_ok" style="flex:1;padding:8px;border:none;border-radius:8px;cursor:pointer;font-weight:700;font-size:13px;color:#fff"></button>
                        </div>
                    </div>
                </div>`;
            document.body.appendChild(el);
        }
        document.getElementById('_cd_title').textContent = title;
        document.getElementById('_cd_msg').textContent = msg;
        document.getElementById('_cd_icon').innerHTML = dangerOk ? '<i class="fas fa-triangle-exclamation" style="color:#ef4444"></i>' : '<i class="fas fa-question-circle" style="color:#3b82f6"></i>';
        const okBtn = document.getElementById('_cd_ok');
        okBtn.textContent = okLabel;
        okBtn.style.background = dangerOk ? '#ef4444' : '#3b82f6';
        el.style.display = 'block';
        const hide = () => el.style.display = 'none';
        const ok = () => { hide(); resolve(true); };
        const cancel = () => { hide(); resolve(false); };
        okBtn.onclick = ok;
        document.getElementById('_cd_cancel').onclick = cancel;
        el.querySelector('div').onclick = (e) => { if (e.target === el.querySelector('div')) cancel(); };
    });
}
