// The registered-user surface: a chat app. A conversation list is the home
// screen; a "+" opens the new-chat sheet (scan / enter / invite); a gear opens
// settings. Selecting a conversation opens it (with an in-header verify). The
// layout is two-pane on wide screens and single-pane (list <-> chat) on narrow.
//
// This replaces the earlier control-panel MainApp. All security-critical wiring
// (send, verify, invite pinning, trust badges) is unchanged; only the shell is.

import { useMemo, useState } from 'react'
import type { Identity } from '../crypto/identity'
import type { Contact } from '../trust/contactStore'
import type { CanaryResult } from '../verify/canary'
import { Conversation } from './Conversation'
import { NewChat } from './NewChat'
import { SafetyNumberView, TrustBadge } from './SafetyNumber'
import { Settings } from './Settings'
import type { Message, MintedInvite, NotifyState } from './useNightjar'

type Overlay = 'none' | 'newchat' | 'settings'

interface Props {
  identity: Identity
  contacts: Contact[]
  conversations: Record<string, Message[]>
  notify: NotifyState
  storagePersisted: boolean | null
  canary: CanaryResult | null
  actions: {
    send: (peer: string, text: string) => void
    startChat: (peer: string) => void
    openFromCode: (input: string) => Promise<string | null>
    mintInvite: () => Promise<MintedInvite | null>
    markVerified: (peer: string) => void
    enableNotifications: () => void
    disableNotifications: () => void
    exportBackup: (passphrase: string) => Promise<boolean>
  }
}

function shortId(id: string): string {
  return `${id.slice(0, 6)}…${id.slice(-4)}`
}

export function Messenger({ identity, contacts, conversations, notify, storagePersisted, canary, actions }: Props) {
  const [selected, setSelected] = useState<string | null>(null)
  const [chatView, setChatView] = useState<'chat' | 'verify'>('chat')
  const [overlay, setOverlay] = useState<Overlay>('none')
  const [minted, setMinted] = useState<MintedInvite | null>(null)

  const contactById = useMemo(() => new Map(contacts.map((c) => [c.peerId, c])), [contacts])

  // Threads = everyone we have a contact for OR a conversation with, newest first.
  const threads = useMemo(() => {
    const ids = new Set<string>([...contacts.map((c) => c.peerId), ...Object.keys(conversations)])
    return [...ids].sort((a, b) => {
      const la = conversations[a]?.at(-1)?.ts ?? 0
      const lb = conversations[b]?.at(-1)?.ts ?? 0
      return lb - la
    })
  }, [contacts, conversations])

  function openChat(peer: string) {
    setSelected(peer)
    setChatView('chat')
    setOverlay('none')
  }

  const selectedContact = selected ? contactById.get(selected) ?? null : null

  // Full-cover overlays sit above the whole messenger.
  if (overlay === 'newchat') {
    return (
      <div className="msgr">
        <NewChat
          minted={minted}
          onMint={() => void actions.mintInvite().then(setMinted)}
          onCode={actions.openFromCode}
          onOpened={openChat}
          onClose={() => setOverlay('none')}
        />
      </div>
    )
  }
  if (overlay === 'settings') {
    return (
      <div className="msgr">
        <Settings
          identity={identity}
          notify={notify}
          storagePersisted={storagePersisted}
          canary={canary}
          onExportBackup={actions.exportBackup}
          onEnableNotifications={actions.enableNotifications}
          onDisableNotifications={actions.disableNotifications}
          onClose={() => setOverlay('none')}
        />
      </div>
    )
  }

  return (
    <div className={`msgr ${selected ? 'has-selection' : ''}`}>
      {/* Conversation list (home). */}
      <div className="msgr-list">
        <div className="msgr-list-head">
          <span className="msgr-title">Chats</span>
          <span className="row">
            <button className="icon-btn" title="settings" onClick={() => setOverlay('settings')}>
              ⚙
            </button>
            <button className="icon-btn primary-icon" title="new chat" onClick={() => setOverlay('newchat')}>
              ＋
            </button>
          </span>
        </div>

        <div className="threads">
          {threads.length === 0 && (
            <div className="threads-empty muted small">
              <p>No conversations yet.</p>
              <button className="primary small" onClick={() => setOverlay('newchat')}>
                start a chat
              </button>
            </div>
          )}
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
                <div className="thread-top">
                  <span className="mono tiny">{shortId(peer)}</span>
                  {c ? <TrustBadge trust={c.trust} /> : <span className="badge badge-unknown">new</span>}
                </div>
                {last && (
                  <span className="muted tiny preview">
                    {last.dir === 'out' ? 'you: ' : ''}
                    {last.text.slice(0, 40)}
                  </span>
                )}
              </button>
            )
          })}
        </div>
      </div>

      {/* Conversation / verify pane. */}
      <div className="msgr-main">
        {!selected ? (
          <div className="empty muted">
            <p>Select a conversation, or start a new one.</p>
          </div>
        ) : chatView === 'verify' && selectedContact ? (
          <SafetyNumberView
            myIkSigPub={identity.ikSig.publicKey}
            contact={selectedContact}
            onVerify={() => actions.markVerified(selectedContact.peerId)}
            onBack={() => setChatView('chat')}
          />
        ) : (
          <Conversation
            peer={selected}
            messages={conversations[selected] ?? []}
            trust={selectedContact?.trust ?? null}
            onSend={(t) => actions.send(selected, t)}
            onVerify={() => selectedContact && setChatView('verify')}
            onBack={() => setSelected(null)}
          />
        )}
      </div>
    </div>
  )
}
