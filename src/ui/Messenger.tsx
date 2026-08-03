// The registered-user surface: a chat app. A conversation list is the home
// screen; a "+" opens the new-chat sheet (scan / enter / invite); a gear opens
// settings. Selecting a conversation opens it (with an in-header verify). The
// layout is two-pane on wide screens and single-pane (list <-> chat) on narrow.
//
// This replaces the earlier control-panel MainApp. All security-critical wiring
// (send, verify, invite pinning, trust badges) is unchanged; only the shell is.

import { useEffect, useMemo, useRef, useState } from 'react'
import type { Identity } from '../crypto/identity'
import type { Contact } from '../trust/contactStore'
import type { CanaryResult } from '../verify/canary'
import { Conversation } from './Conversation'
import type { DeviceRow } from './DevicesPanel'
import { NewChat } from './NewChat'
import { SafetyNumberView, TrustBadge } from './SafetyNumber'
import { Settings } from './Settings'
import type { Message, MintedInvite, NotifyState } from './useNightjar'

type Overlay = 'none' | 'newchat' | 'settings'

interface Props {
  identity: Identity
  contacts: Contact[]
  aliases: Record<string, string>
  conversations: Record<string, Message[]>
  /** Relay connection state. Surfaced inside a conversation because on a phone the
   *  global topbar (which carries the dot) steps aside for the chat. */
  connected: boolean
  /** The peer of the most recent full delete, from THIS tab or a sibling. `selected`
   *  is per-tab state that a cross-tab render event cannot reach, so this is what
   *  closes a pane whose conversation no longer exists. */
  removedPeer: { peer: string; n: number } | null
  notify: NotifyState
  storagePersisted: boolean | null
  canary: CanaryResult | null
  bioAvailable: boolean
  lockMethods: Array<'pass' | 'pin' | 'bio'>
  moveExported: boolean
  moveProgress: { done: number; total: number } | null
  actions: {
    send: (peer: string, text: string, ephemeral?: boolean) => void
    deleteMessage: (peer: string, id: string, failed?: boolean) => void
    startChat: (peer: string) => void
    openFromCode: (input: string) => Promise<string | null>
    renameChat: (peer: string, name: string) => void
    mintInvite: () => Promise<MintedInvite | null>
    syncInviteContacts: () => Promise<number>
    markVerified: (peer: string) => void
    unverify: (peer: string) => void
    clearMessages: (peer: string) => void
    deleteConversation: (peer: string) => void
    ensureContact: (peer: string) => Promise<boolean>
    enableNotifications: () => void
    disableNotifications: () => void
    exportBackup: (passphrase: string) => Promise<boolean>
    prepareMove: () => Promise<
      | { ok: true; messages: number; contacts: number; unreadable: number; orphaned: number; bytes: number }
      | { ok: false; blocked: 'outbox' | 'too-large'; count: number }
      | null
    >
    createMove: (passphrase: string) => Promise<boolean>
    eraseThisDevice: () => Promise<void>
    listDevices: () => Promise<DeviceRow[]>
    removeDevice: (deviceId: string) => Promise<boolean>
    authorizeNewDevice: (codeText: string) => Promise<{ deviceId: string; secret: Uint8Array } | null>
    sealLinkTransfer: (secret: Uint8Array) => Promise<Uint8Array | null>
    sendLinkOverRelay: (deviceId: string, secret: Uint8Array) => Promise<boolean>
    addBiometric: () => void
    removeBiometric: () => void
  }
}

function shortId(id: string): string {
  return `${id.slice(0, 6)}…${id.slice(-4)}`
}

export function Messenger({ identity, connected, removedPeer, contacts, aliases, conversations, notify, storagePersisted, canary, bioAvailable, lockMethods, moveExported, moveProgress, actions }: Props) {
  const displayName = (peer: string): string => aliases[peer]?.trim() || shortId(peer)
  const [selected, setSelected] = useState<string | null>(null)
  const [chatView, setChatView] = useState<'chat' | 'verify'>('chat')
  const [overlay, setOverlay] = useState<Overlay>('none')
  const [minted, setMinted] = useState<MintedInvite | null>(null)
  const [unread, setUnread] = useState<Set<string>>(() => new Set())

  const contactById = useMemo(() => new Map(contacts.map((c) => [c.peerId, c])), [contacts])

  // Track unread ("new message") chats. The first render seeds the baseline from
  // the already-hydrated history (so past messages are not marked new); after
  // that, a peer whose message count grows with an INBOUND message, while it is
  // not the open chat, is flagged. Opening a chat clears its flag.
  const prevCounts = useRef<Record<string, number> | null>(null)
  useEffect(() => {
    const counts: Record<string, number> = {}
    for (const [p, msgs] of Object.entries(conversations)) counts[p] = msgs.length
    const prev = prevCounts.current
    prevCounts.current = counts
    if (!prev) return // baseline: hydrated history is already "read"
    const fresh: string[] = []
    for (const [p, c] of Object.entries(counts)) {
      const before = prev[p] ?? 0
      if (c > before && p !== selected && (conversations[p] ?? []).slice(before).some((m) => m.dir === 'in')) {
        fresh.push(p)
      }
    }
    if (fresh.length) {
      setUnread((u) => {
        const n = new Set(u)
        for (const p of fresh) n.add(p)
        return n
      })
    }
  }, [conversations, selected])

  // A conversation deleted here or in another tab must not stay open: the pane would
  // show an empty chat with no contact and no trust badge, and typing in it would
  // re-create the contact and a session as though the user had asked for it.
  useEffect(() => {
    if (!removedPeer) return
    setUnread((u) => {
      if (!u.has(removedPeer.peer)) return u
      const n = new Set(u)
      n.delete(removedPeer.peer)
      return n
    })
    setSelected((cur) => (cur === removedPeer.peer ? null : cur))
  }, [removedPeer])

  const clearUnread = (peer: string) =>
    setUnread((u) => {
      if (!u.has(peer)) return u
      const n = new Set(u)
      n.delete(peer)
      return n
    })

  // Threads = everyone we have a contact for, a conversation with, OR a name for
  // (a named chat persists in the list even before a message or contact record),
  // newest-conversation first.
  const threads = useMemo(() => {
    const ids = new Set<string>([
      ...contacts.map((c) => c.peerId),
      ...Object.keys(conversations),
      ...Object.keys(aliases),
    ])
    return [...ids].sort((a, b) => {
      const la = conversations[a]?.at(-1)?.ts ?? 0
      const lb = conversations[b]?.at(-1)?.ts ?? 0
      return lb - la
    })
  }, [contacts, conversations, aliases])

  function openChat(peer: string) {
    clearUnread(peer)
    setSelected(peer)
    setChatView('chat')
    setOverlay('none')
  }

  const selectedContact = selected ? contactById.get(selected) ?? null : null

  // Open the verify screen. If we do not hold a contact record yet (e.g. this peer
  // was just added by their code/QR and no message has been exchanged), fetch their
  // key + record a TOFU contact first, so the safety number can render instead of the
  // verify button silently doing nothing.
  async function openVerify() {
    if (!selected) return
    if (!selectedContact) {
      const ok = await actions.ensureContact(selected)
      if (!ok) return // a notice was shown
    }
    setChatView('verify')
  }

  // Full-cover overlays sit above the whole messenger.
  if (overlay === 'newchat') {
    return (
      <div className="msgr">
        <NewChat
          minted={minted}
          onMint={() => void actions.mintInvite().then(setMinted)}
          onSync={actions.syncInviteContacts}
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
          bioAvailable={bioAvailable}
          lockMethods={lockMethods}
          moveExported={moveExported}
          moveProgress={moveProgress}
          onExportBackup={actions.exportBackup}
          onPrepareMove={actions.prepareMove}
          onCreateMove={actions.createMove}
          onEraseDevice={actions.eraseThisDevice}
          onListDevices={actions.listDevices}
          onRemoveDevice={actions.removeDevice}
          onAuthorizeDevice={actions.authorizeNewDevice}
          onSealLink={actions.sealLinkTransfer}
          onSendLinkOverRelay={actions.sendLinkOverRelay}
          onEnableNotifications={actions.enableNotifications}
          onDisableNotifications={actions.disableNotifications}
          onAddBiometric={actions.addBiometric}
          onRemoveBiometric={actions.removeBiometric}
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
            const isUnread = unread.has(peer) && selected !== peer
            return (
              <button
                key={peer}
                className={`thread ${selected === peer ? 'thread-active' : ''} ${isUnread ? 'thread-unread' : ''}`}
                onClick={() => openChat(peer)}
              >
                <div className="thread-top">
                  <span className="thread-left">
                    {isUnread && <span className="unread-dot" title="new messages" />}
                    <span className="thread-name">{displayName(peer)}</span>
                  </span>
                  {c ? <TrustBadge trust={c.trust} /> : <span className="badge badge-unknown">new</span>}
                </div>
                {aliases[peer]?.trim() && <span className="mono tiny muted">{shortId(peer)}</span>}
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
            name={aliases[selectedContact.peerId]?.trim() || ''}
            onVerify={() => actions.markVerified(selectedContact.peerId)}
            onUnverify={() => actions.unverify(selectedContact.peerId)}
            onBack={() => setChatView('chat')}
          />
        ) : (
          <Conversation
            // Remount per peer so the compose draft AND the sticky session-only mode
            // reset to their safe defaults on every conversation switch (a session-only
            // toggle must never silently follow you from one chat to another).
            key={selected}
            peer={selected}
            connected={connected}
            name={aliases[selected]?.trim() || ''}
            messages={conversations[selected] ?? []}
            trust={selectedContact?.trust ?? null}
            onSend={(t, ephemeral) => actions.send(selected, t, ephemeral)}
            onVerify={() => void openVerify()}
            onRename={(n) => actions.renameChat(selected, n)}
            onDelete={(id, failed) => void actions.deleteMessage(selected, id, failed)}
            onClearMessages={() => actions.clearMessages(selected)}
            onDeleteConversation={() => {
              // Drop this pane's own per-peer state too, or the thread stays
              // selected and flagged unread after the data behind it is gone.
              setUnread((u) => {
                if (!u.has(selected)) return u
                const n = new Set(u)
                n.delete(selected)
                return n
              })
              setSelected(null)
              actions.deleteConversation(selected)
            }}
            onBack={() => setSelected(null)}
          />
        )}
      </div>
    </div>
  )
}
