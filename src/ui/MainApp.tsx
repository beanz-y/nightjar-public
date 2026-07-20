// The registered-user screen: a contact list with per-direction trust badges, a
// conversation pane, the invite panel, and the safety-number verify view. Kept
// deliberately minimal (this is the P5 trust surface, not the full P6 chat app).

import { useMemo, useState } from 'react'
import type { Identity } from '../crypto/identity'
import type { Contact } from '../trust/contactStore'
import { BackupPanel } from './BackupPanel'
import { Conversation } from './Conversation'
import { InvitePanel } from './InvitePanel'
import { NotifySettings } from './NotifySettings'
import { SafetyNumberView, TrustBadge } from './SafetyNumber'
import type { Message, MintedInvite, NotifyState } from './useNightjar'

const USER_ID_RE = /^[a-z2-7]{52}$/

interface Props {
  identity: Identity
  contacts: Contact[]
  conversations: Record<string, Message[]>
  notify: NotifyState
  storagePersisted: boolean | null
  actions: {
    send: (peer: string, text: string) => void
    startChat: (peer: string) => void
    mintInvite: () => Promise<MintedInvite | null>
    markVerified: (peer: string) => void
    enableNotifications: () => void
    disableNotifications: () => void
    exportBackup: (passphrase: string) => Promise<boolean>
  }
}

export function MainApp({ identity, contacts, conversations, notify, storagePersisted, actions }: Props) {
  const [selected, setSelected] = useState<string | null>(null)
  const [view, setView] = useState<'chat' | 'verify'>('chat')
  const [inviteOpen, setInviteOpen] = useState(false)
  const [backupOpen, setBackupOpen] = useState(false)
  const [minted, setMinted] = useState<MintedInvite | null>(null)
  const [newPeer, setNewPeer] = useState('')

  const contactById = useMemo(() => new Map(contacts.map((c) => [c.peerId, c])), [contacts])

  // Threads = everyone we have a contact for OR a conversation with.
  const threads = useMemo(() => {
    const ids = new Set<string>([...contacts.map((c) => c.peerId), ...Object.keys(conversations)])
    return [...ids].sort()
  }, [contacts, conversations])

  function openChat(peer: string) {
    setSelected(peer)
    setView('chat')
  }

  function startNewChat() {
    const peer = newPeer.trim().toLowerCase()
    if (!USER_ID_RE.test(peer)) return
    if (peer === identity.userId) return
    actions.startChat(peer)
    setNewPeer('')
    openChat(peer)
  }

  async function mint() {
    setMinted(await actions.mintInvite())
  }

  const selectedContact = selected ? contactById.get(selected) ?? null : null

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="me">
          <div className="field-label small muted">you</div>
          <div className="mono break tiny">{identity.userId}</div>
        </div>

        <button
          className="primary block"
          onClick={() => {
            setInviteOpen(true)
            setMinted(null)
          }}
        >
          invite someone
        </button>

        <div className="newchat">
          <div className="field-label small muted">message a user id</div>
          <div className="row">
            <input
              className="mono tiny"
              placeholder="their 52-char id"
              value={newPeer}
              onChange={(e) => setNewPeer(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') startNewChat()
              }}
            />
            <button className="ghost small" disabled={!USER_ID_RE.test(newPeer.trim().toLowerCase())} onClick={startNewChat}>
              go
            </button>
          </div>
        </div>

        <div className="threads">
          {threads.length === 0 && <p className="muted small">No conversations yet. Invite someone, or start one with their id.</p>}
          {threads.map((peer) => {
            const c = contactById.get(peer)
            const msgs = conversations[peer] ?? []
            const last = msgs[msgs.length - 1]
            return (
              <button
                key={peer}
                className={`thread ${selected === peer ? 'thread-active' : ''}`}
                onClick={() => openChat(peer)}
              >
                <div className="mono tiny break">{peer.slice(0, 20)}…</div>
                <div className="thread-meta">
                  {c ? <TrustBadge trust={c.trust} /> : <span className="badge badge-unknown">new</span>}
                  {last && <span className="muted tiny preview">{last.dir === 'out' ? 'you: ' : ''}{last.text.slice(0, 24)}</span>}
                </div>
              </button>
            )
          })}
        </div>

        <NotifySettings notify={notify} onEnable={actions.enableNotifications} onDisable={actions.disableNotifications} />

        <button
          className="ghost block"
          onClick={() => {
            setBackupOpen(true)
            setInviteOpen(false)
          }}
        >
          back up identity
        </button>
        {storagePersisted === false && !backupOpen && (
          <p className="muted tiny">storage is not persistent in this browser; keep a backup</p>
        )}
      </aside>

      <main className="pane">
        {backupOpen ? (
          <BackupPanel onExport={actions.exportBackup} storagePersisted={storagePersisted} onClose={() => setBackupOpen(false)} />
        ) : inviteOpen ? (
          <InvitePanel minted={minted} onMint={() => void mint()} onClose={() => setInviteOpen(false)} />
        ) : !selected ? (
          <div className="empty muted">
            <p>Select a conversation, or invite someone to start.</p>
          </div>
        ) : view === 'verify' && selectedContact ? (
          <SafetyNumberView
            myIkSigPub={identity.ikSig.publicKey}
            contact={selectedContact}
            onVerify={() => actions.markVerified(selectedContact.peerId)}
            onBack={() => setView('chat')}
          />
        ) : (
          <Conversation
            peer={selected}
            messages={conversations[selected] ?? []}
            trust={selectedContact?.trust ?? null}
            onSend={(t) => actions.send(selected, t)}
            onVerify={() => {
              if (selectedContact) setView('verify')
            }}
          />
        )}
      </main>
    </div>
  )
}
