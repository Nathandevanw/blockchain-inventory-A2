// frontend/js/main.js

document.getElementById('addForm').addEventListener('submit', async e => {
  e.preventDefault();

  // 1. Gather form values
  const fm = new FormData(e.target);
  const payload = {
    node: fm.get('node'),
    record: {
      id:   fm.get('id'),
      qty:  Number(fm.get('qty')),
      price:Number(fm.get('price'))
    }
  };

  // 2. Call your Flask endpoint
  const res = await fetch('/api/add_record', {
    method:      'POST',
    headers:     { 'Content-Type': 'application/json' },
    body:        JSON.stringify(payload),
  });

  // 3. Display the result
  const text = await (res.ok ? res.text() : res.text());
  document.getElementById('result').textContent = 
    res.ok
      ? `✔ ${text}`
      : `✘ ${res.status}: ${text}`;
});
