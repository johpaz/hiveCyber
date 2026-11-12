/** Small bottom-right toast so feedback is visible wherever the user is scrolled. */
export function toast(text: string, bad = false) {
  const el = Object.assign(document.createElement('div'), { className: `toast ${bad ? 'bad' : 'ok'}`, textContent: text });
  document.body.append(el);
  requestAnimationFrame(() => el.classList.add('show'));
  setTimeout(() => {
    el.classList.remove('show');
    setTimeout(() => el.remove(), 300);
  }, bad ? 6000 : 3500);
}

export interface LiveModels { source: string; models: { id: string; size_gb?: number | null }[] }
