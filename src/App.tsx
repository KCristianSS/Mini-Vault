/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { 
  Lock, 
  Unlock, 
  Plus, 
  Search, 
  Eye, 
  EyeOff, 
  Edit2, 
  Trash2, 
  ExternalLink, 
  LogOut, 
  Shield, 
  Clock,
  ChevronRight,
  AlertCircle,
  Loader2,
  Key
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { cn } from './lib/utils';

// --- Types ---
interface Credential {
  id: number;
  service_name: string;
  account_username: string;
  url: string;
  notes: string;
  created_at: string;
  updated_at: string;
  password?: string;
}

interface User {
  id: number;
  email: string;
}

// --- Components ---

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('vault_token'));
  const [view, setView] = useState<'login' | 'register' | 'dashboard' | 'form' | 'detail'>('login');
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCred, setSelectedCred] = useState<Credential | null>(null);
  const [isEditing, setIsEditing] = useState(false);
  const [revealedPasswords, setRevealedPasswords] = useState<Record<number, string>>({});

  useEffect(() => {
    if (token) {
      const savedUser = localStorage.getItem('vault_user');
      if (savedUser) setUser(JSON.parse(savedUser));
      setView('dashboard');
      fetchCredentials();
    }
  }, [token]);

  const fetchCredentials = async () => {
    if (!token) return;
    setLoading(true);
    try {
      const res = await fetch('/api/credentials', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setCredentials(data);
      }
    } catch (err) {
      setError('Failed to fetch credentials');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('vault_token');
    localStorage.removeItem('vault_user');
    setToken(null);
    setUser(null);
    setView('login');
    setCredentials([]);
  };

  const revealPassword = async (id: number) => {
    if (revealedPasswords[id]) {
      const newRevealed = { ...revealedPasswords };
      delete newRevealed[id];
      setRevealedPasswords(newRevealed);
      return;
    }

    try {
      const res = await fetch(`/api/credentials/${id}?reveal=true`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setRevealedPasswords({ ...revealedPasswords, [id]: data.password });
      }
    } catch (err) {
      setError('Failed to reveal password');
    }
  };

  const deleteCredential = async (id: number) => {
    if (!confirm('Are you sure you want to delete this credential?')) return;
    try {
      const res = await fetch(`/api/credentials/${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        setCredentials(credentials.filter(c => c.id !== id));
        if (selectedCred?.id === id) setView('dashboard');
      }
    } catch (err) {
      setError('Failed to delete credential');
    }
  };

  const filteredCredentials = credentials.filter(c => 
    c.service_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    c.account_username?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-[#F5F5F0] text-[#1A1A1A] font-sans selection:bg-emerald-100">
      {/* Navigation */}
      <nav className="sticky top-0 z-50 bg-white/80 backdrop-blur-md border-b border-black/5 px-6 py-4 flex justify-between items-center">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 bg-black rounded-lg flex items-center justify-center">
            <Shield className="text-white w-5 h-5" />
          </div>
          <h1 className="text-xl font-semibold tracking-tight">Mini Vault</h1>
        </div>
        {user && (
          <div className="flex items-center gap-4">
            <span className="text-sm text-black/50 font-medium">{user.email}</span>
            <button 
              onClick={handleLogout}
              className="p-2 hover:bg-black/5 rounded-full transition-colors"
              title="Logout"
            >
              <LogOut className="w-5 h-5" />
            </button>
          </div>
        )}
      </nav>

      <main className="max-w-5xl mx-auto p-6">
        <AnimatePresence mode="wait">
          {view === 'login' || view === 'register' ? (
            <AuthView 
              type={view} 
              onSuccess={(t, u) => {
                localStorage.setItem('vault_token', t);
                localStorage.setItem('vault_user', JSON.stringify(u));
                setToken(t);
                setUser(u);
              }} 
              onToggle={() => setView(view === 'login' ? 'register' : 'login')}
            />
          ) : view === 'dashboard' ? (
            <motion.div 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="space-y-8"
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <h2 className="text-3xl font-bold tracking-tight">Your Vault</h2>
                  <p className="text-black/50">Securely managing {credentials.length} services</p>
                </div>
                <button 
                  onClick={() => { setIsEditing(false); setSelectedCred(null); setView('form'); }}
                  className="bg-black text-white px-6 py-3 rounded-2xl font-medium flex items-center gap-2 hover:bg-black/80 transition-all active:scale-95 shadow-lg shadow-black/10"
                >
                  <Plus className="w-5 h-5" />
                  Add Credential
                </button>
              </div>

              <div className="relative">
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-black/30 w-5 h-5" />
                <input 
                  type="text" 
                  placeholder="Search services..." 
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full bg-white border border-black/5 rounded-2xl py-4 pl-12 pr-4 focus:outline-none focus:ring-2 focus:ring-black/5 transition-all shadow-sm"
                />
              </div>

              {loading ? (
                <div className="flex flex-col items-center justify-center py-20 gap-4">
                  <Loader2 className="w-8 h-8 animate-spin text-black/20" />
                  <p className="text-black/40 font-medium">Unlocking your vault...</p>
                </div>
              ) : filteredCredentials.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {filteredCredentials.map((cred) => (
                    <CredentialCard 
                      key={cred.id} 
                      cred={cred} 
                      onDetail={() => { setSelectedCred(cred); setView('detail'); }}
                      onEdit={() => { setSelectedCred(cred); setIsEditing(true); setView('form'); }}
                      onDelete={() => deleteCredential(cred.id)}
                    />
                  ))}
                </div>
              ) : (
                <div className="bg-white border border-dashed border-black/10 rounded-3xl p-20 text-center space-y-4">
                  <div className="w-16 h-16 bg-black/5 rounded-full flex items-center justify-center mx-auto">
                    <Key className="text-black/20 w-8 h-8" />
                  </div>
                  <h3 className="text-xl font-semibold">No credentials found</h3>
                  <p className="text-black/40 max-w-xs mx-auto">Start by adding your first service to the vault.</p>
                </div>
              )}
            </motion.div>
          ) : view === 'form' ? (
            <CredentialForm 
              initialData={isEditing ? selectedCred : null}
              token={token!}
              onCancel={() => setView('dashboard')}
              onSuccess={() => { fetchCredentials(); setView('dashboard'); }}
            />
          ) : view === 'detail' && selectedCred ? (
            <CredentialDetail 
              cred={selectedCred}
              token={token!}
              revealedPassword={revealedPasswords[selectedCred.id]}
              onReveal={() => revealPassword(selectedCred.id)}
              onBack={() => setView('dashboard')}
              onEdit={() => { setIsEditing(true); setView('form'); }}
              onDelete={() => deleteCredential(selectedCred.id)}
            />
          ) : null}
        </AnimatePresence>
      </main>

      {error && (
        <div className="fixed bottom-6 right-6 bg-red-500 text-white px-6 py-4 rounded-2xl shadow-2xl flex items-center gap-3 animate-in slide-in-from-bottom-4">
          <AlertCircle className="w-5 h-5" />
          <p className="font-medium">{error}</p>
          <button onClick={() => setError(null)} className="ml-4 opacity-50 hover:opacity-100">✕</button>
        </div>
      )}
    </div>
  );
}

// --- Sub-components ---

function AuthView({ type, onSuccess, onToggle }: { type: 'login' | 'register', onSuccess: (t: string, u: User) => void, onToggle: () => void }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const endpoint = type === 'login' ? '/api/auth/login' : '/api/auth/register';
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const data = await res.json();

      if (res.ok) {
        if (type === 'login') {
          onSuccess(data.token, data.user);
        } else {
          onToggle(); // Go to login after register
        }
      } else {
        setError(data.error || 'Authentication failed');
      }
    } catch (err) {
      setError('Server connection failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.div 
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className="max-w-md mx-auto mt-20"
    >
      <div className="bg-white p-8 rounded-[32px] shadow-xl shadow-black/5 border border-black/5">
        <div className="text-center mb-8">
          <div className="w-16 h-16 bg-black rounded-2xl flex items-center justify-center mx-auto mb-4">
            <Lock className="text-white w-8 h-8" />
          </div>
          <h2 className="text-2xl font-bold tracking-tight">{type === 'login' ? 'Welcome Back' : 'Create Account'}</h2>
          <p className="text-black/40 mt-1">Enter your master credentials to continue</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1">
            <label className="text-xs font-bold uppercase tracking-wider text-black/40 ml-1">Email Address</label>
            <input 
              type="email" 
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full bg-[#F5F5F0] border-none rounded-2xl py-4 px-5 focus:ring-2 focus:ring-black/5 transition-all"
              placeholder="name@example.com"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-bold uppercase tracking-wider text-black/40 ml-1">Master Password</label>
            <input 
              type="password" 
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-[#F5F5F0] border-none rounded-2xl py-4 px-5 focus:ring-2 focus:ring-black/5 transition-all"
              placeholder="••••••••"
            />
          </div>

          {error && (
            <div className="bg-red-50 text-red-500 p-4 rounded-2xl text-sm font-medium flex items-center gap-2">
              <AlertCircle className="w-4 h-4" />
              {error}
            </div>
          )}

          <button 
            disabled={loading}
            className="w-full bg-black text-white py-4 rounded-2xl font-bold hover:bg-black/80 transition-all active:scale-[0.98] disabled:opacity-50 flex items-center justify-center gap-2"
          >
            {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : (type === 'login' ? 'Unlock Vault' : 'Create Vault')}
          </button>
        </form>

        <div className="mt-8 pt-6 border-t border-black/5 text-center">
          <button 
            onClick={onToggle}
            className="text-sm font-semibold text-black/60 hover:text-black transition-colors"
          >
            {type === 'login' ? "Don't have a vault? Create one" : "Already have a vault? Sign in"}
          </button>
        </div>
      </div>
    </motion.div>
  );
}

interface CredentialCardProps {
  key?: React.Key;
  cred: Credential;
  onDetail: () => void;
  onEdit: () => void;
  onDelete: () => void | Promise<void>;
}

function CredentialCard({ cred, onDetail, onEdit, onDelete }: CredentialCardProps) {
  return (
    <motion.div 
      layout
      whileHover={{ y: -4 }}
      className="bg-white p-6 rounded-3xl border border-black/5 shadow-sm hover:shadow-md transition-all group cursor-pointer"
      onClick={onDetail}
    >
      <div className="flex justify-between items-start mb-4">
        <div className="w-12 h-12 bg-[#F5F5F0] rounded-2xl flex items-center justify-center group-hover:bg-black group-hover:text-white transition-colors">
          <Shield className="w-6 h-6" />
        </div>
        <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity" onClick={e => e.stopPropagation()}>
          <button onClick={onEdit} className="p-2 hover:bg-black/5 rounded-lg transition-colors"><Edit2 className="w-4 h-4" /></button>
          <button onClick={onDelete} className="p-2 hover:bg-red-50 text-red-500 rounded-lg transition-colors"><Trash2 className="w-4 h-4" /></button>
        </div>
      </div>
      
      <h3 className="text-lg font-bold tracking-tight mb-1">{cred.service_name}</h3>
      <p className="text-sm text-black/40 font-medium truncate mb-4">{cred.account_username || 'No username'}</p>
      
      <div className="flex items-center justify-between pt-4 border-t border-black/5">
        <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-widest text-black/30">
          <Clock className="w-3 h-3" />
          {new Date(cred.updated_at).toLocaleDateString()}
        </div>
        <ChevronRight className="w-4 h-4 text-black/20" />
      </div>
    </motion.div>
  );
}

function CredentialForm({ initialData, token, onCancel, onSuccess }: { initialData: Credential | null, token: string, onCancel: () => void, onSuccess: () => void }) {
  const [formData, setFormData] = useState({
    serviceName: initialData?.service_name || '',
    accountUsername: initialData?.account_username || '',
    password: '',
    url: initialData?.url || '',
    notes: initialData?.notes || ''
  });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const method = initialData ? 'PUT' : 'POST';
      const url = initialData ? `/api/credentials/${initialData.id}` : '/api/credentials';
      const res = await fetch(url, {
        method,
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(formData)
      });
      if (res.ok) onSuccess();
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="max-w-2xl mx-auto"
    >
      <div className="bg-white p-8 rounded-[32px] border border-black/5 shadow-xl">
        <h2 className="text-2xl font-bold mb-8">{initialData ? 'Edit Credential' : 'Add New Credential'}</h2>
        
        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-1">
              <label className="text-xs font-bold uppercase tracking-wider text-black/40 ml-1">Service Name</label>
              <input 
                required
                value={formData.serviceName}
                onChange={e => setFormData({ ...formData, serviceName: e.target.value })}
                className="w-full bg-[#F5F5F0] border-none rounded-2xl py-4 px-5 focus:ring-2 focus:ring-black/5 transition-all"
                placeholder="e.g. Netflix"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-bold uppercase tracking-wider text-black/40 ml-1">Username / Email</label>
              <input 
                value={formData.accountUsername}
                onChange={e => setFormData({ ...formData, accountUsername: e.target.value })}
                className="w-full bg-[#F5F5F0] border-none rounded-2xl py-4 px-5 focus:ring-2 focus:ring-black/5 transition-all"
                placeholder="user@example.com"
              />
            </div>
          </div>

          <div className="space-y-1">
            <label className="text-xs font-bold uppercase tracking-wider text-black/40 ml-1">Password</label>
            <input 
              type="password"
              required={!initialData}
              value={formData.password}
              onChange={e => setFormData({ ...formData, password: e.target.value })}
              className="w-full bg-[#F5F5F0] border-none rounded-2xl py-4 px-5 focus:ring-2 focus:ring-black/5 transition-all"
              placeholder={initialData ? "Leave blank to keep current" : "••••••••"}
            />
          </div>

          <div className="space-y-1">
            <label className="text-xs font-bold uppercase tracking-wider text-black/40 ml-1">Service URL (Optional)</label>
            <input 
              value={formData.url}
              onChange={e => setFormData({ ...formData, url: e.target.value })}
              className="w-full bg-[#F5F5F0] border-none rounded-2xl py-4 px-5 focus:ring-2 focus:ring-black/5 transition-all"
              placeholder="https://..."
            />
          </div>

          <div className="space-y-1">
            <label className="text-xs font-bold uppercase tracking-wider text-black/40 ml-1">Notes (Optional)</label>
            <textarea 
              value={formData.notes}
              onChange={e => setFormData({ ...formData, notes: e.target.value })}
              rows={3}
              className="w-full bg-[#F5F5F0] border-none rounded-2xl py-4 px-5 focus:ring-2 focus:ring-black/5 transition-all resize-none"
              placeholder="Any extra details..."
            />
          </div>

          <div className="flex gap-4 pt-4">
            <button 
              type="button"
              onClick={onCancel}
              className="flex-1 bg-[#F5F5F0] text-black py-4 rounded-2xl font-bold hover:bg-black/5 transition-all"
            >
              Cancel
            </button>
            <button 
              disabled={loading}
              className="flex-[2] bg-black text-white py-4 rounded-2xl font-bold hover:bg-black/80 transition-all active:scale-[0.98] disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : (initialData ? 'Save Changes' : 'Add to Vault')}
            </button>
          </div>
        </form>
      </div>
    </motion.div>
  );
}

function CredentialDetail({ cred, token, revealedPassword, onReveal, onBack, onEdit, onDelete }: { 
  cred: Credential, 
  token: string, 
  revealedPassword?: string, 
  onReveal: () => void, 
  onBack: () => void,
  onEdit: () => void,
  onDelete: () => void | Promise<void>
}) {
  return (
    <motion.div 
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className="max-w-2xl mx-auto"
    >
      <div className="bg-white rounded-[40px] border border-black/5 shadow-2xl overflow-hidden">
        <div className="bg-black p-12 text-white relative">
          <button onClick={onBack} className="absolute top-8 left-8 p-2 hover:bg-white/10 rounded-full transition-colors">
            <ChevronRight className="w-6 h-6 rotate-180" />
          </button>
          <div className="flex flex-col items-center text-center space-y-4">
            <div className="w-20 h-20 bg-white/10 rounded-3xl flex items-center justify-center backdrop-blur-sm">
              <Shield className="w-10 h-10" />
            </div>
            <div>
              <h2 className="text-3xl font-bold tracking-tight">{cred.service_name}</h2>
              <p className="text-white/40 font-medium">{cred.account_username || 'No username'}</p>
            </div>
          </div>
        </div>

        <div className="p-12 space-y-10">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-10">
            <DetailItem label="Username" value={cred.account_username || 'Not set'} />
            <DetailItem label="Last Updated" value={new Date(cred.updated_at).toLocaleString()} />
          </div>

          <div className="space-y-3">
            <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-black/30">Password</label>
            <div className="flex items-center gap-4 bg-[#F5F5F0] p-6 rounded-3xl group">
              <div className="flex-1 font-mono text-lg tracking-wider">
                {revealedPassword ? revealedPassword : '••••••••••••'}
              </div>
              <button 
                onClick={onReveal}
                className="p-3 bg-white rounded-2xl shadow-sm hover:shadow-md transition-all active:scale-90"
              >
                {revealedPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>
          </div>

          {cred.url && (
            <div className="space-y-3">
              <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-black/30">Website</label>
              <a 
                href={cred.url} 
                target="_blank" 
                rel="noopener noreferrer"
                className="flex items-center justify-between bg-[#F5F5F0] p-6 rounded-3xl hover:bg-black/5 transition-colors group"
              >
                <span className="font-medium truncate">{cred.url}</span>
                <ExternalLink className="w-5 h-5 text-black/20 group-hover:text-black transition-colors" />
              </a>
            </div>
          )}

          {cred.notes && (
            <div className="space-y-3">
              <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-black/30">Notes</label>
              <div className="bg-[#F5F5F0] p-6 rounded-3xl text-sm leading-relaxed whitespace-pre-wrap">
                {cred.notes}
              </div>
            </div>
          )}

          <div className="flex gap-4 pt-6">
            <button 
              onClick={onEdit}
              className="flex-1 bg-black text-white py-4 rounded-2xl font-bold hover:bg-black/80 transition-all flex items-center justify-center gap-2"
            >
              <Edit2 className="w-4 h-4" />
              Edit
            </button>
            <button 
              onClick={onDelete}
              className="flex-1 bg-red-50 text-red-500 py-4 rounded-2xl font-bold hover:bg-red-100 transition-all flex items-center justify-center gap-2"
            >
              <Trash2 className="w-4 h-4" />
              Delete
            </button>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

function DetailItem({ label, value }: { label: string, value: string }) {
  return (
    <div className="space-y-1">
      <label className="text-[10px] font-bold uppercase tracking-[0.2em] text-black/30">{label}</label>
      <p className="font-semibold text-lg">{value}</p>
    </div>
  );
}
