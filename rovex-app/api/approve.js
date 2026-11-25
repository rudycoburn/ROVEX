const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');
module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const { data: { user } } = await sb.auth.getUser(token);
  if (!user || user.email !== process.env.ADMIN_EMAIL) return res.status(403).json({ error: 'Forbidden' });
  const { id, action } = req.body || {};
  const { data: row } = await sb.from('access_requests').select('*').eq('id', id).single();
  if (!row) return res.status(404).json({ error: 'Request not found' });
  const now = new Date().toISOString();
  const setStatus = (status, extra = {}) => sb.from('access_requests').update({ status, decided_at: now, ...extra }).eq('id', id);
  try {
    if (action === 'approve') {
      const password = crypto.randomBytes(9).toString('base64url');
      const { data, error } = await sb.auth.admin.createUser({ email: row.email, password, email_confirm: true });
      if (error) throw error;
      await setStatus('approved', { user_id: data.user.id });
      return res.json({ ok: true, password });
    }
    if (action === 'reject') { await setStatus('rejected'); return res.json({ ok: true }); }
    if (action === 'suspend' || action === 'reinstate') {
      if (row.user_id) await sb.auth.admin.updateUserById(row.user_id, { ban_duration: action === 'suspend' ? '876000h' : 'none' });
      await setStatus(action === 'suspend' ? 'suspended' : 'approved');
      return res.json({ ok: true });
    }
    if (action === 'delete') {
      if (row.user_id) await sb.auth.admin.deleteUser(row.user_id);
      await sb.from('access_requests').delete().eq('id', id);
      return res.json({ ok: true });
    }
    return res.status(400).json({ error: 'Unknown action' });
  } catch (e) { return res.status(500).json({ error: e.message }); }
};
