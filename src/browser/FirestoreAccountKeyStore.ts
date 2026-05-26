import {
  doc,
  getDoc,
  setDoc,
  runTransaction,
  onSnapshot,
  collection,
  query,
  where,
  deleteDoc,
  getDocs,
  writeBatch,
  updateDoc
} from "firebase/firestore";
import { getDb, getAuth } from "../config";
import type { AccountKeyStore } from "../core/interfaces";
import type { AccountKeysDocument, KeystoreEntry, PendingDevice } from "../core/types";

export class FirestoreAccountKeyStore implements AccountKeyStore {
  private getUid(): string {
    const user = getAuth().currentUser;
    if (!user) {
      throw new Error("Must be signed in to perform this operation.");
    }
    return user.uid;
  }

  async getAccountKeys(): Promise<AccountKeysDocument | null> {
    const uid = this.getUid();
    const ref = doc(getDb(), "users", uid, "account_keys", "default");
    
    let attempts = 0;
    const maxAttempts = 5;
    let delay = 100;
    
    while (true) {
      try {
        const snap = await getDoc(ref);
        if (!snap.exists()) return null;
        return snap.data() as AccountKeysDocument;
      } catch (e: any) {
        attempts++;
        const isPermissionDenied = e.code === "permission-denied" || e.message?.toLowerCase().includes("permission-denied");
        if (isPermissionDenied && attempts < maxAttempts) {
          console.warn(`[FirestoreAccountKeyStore] Transient permission-denied detected (attempt ${attempts}/${maxAttempts}). Retrying getAccountKeys in ${delay}ms...`);
          await new Promise(resolve => setTimeout(resolve, delay));
          delay *= 2;
          continue;
        }
        throw e;
      }
    }
  }

  async transactAccountKeys(
    updater: (current: AccountKeysDocument) => AccountKeysDocument | Promise<AccountKeysDocument>
  ): Promise<void> {
    const uid = this.getUid();
    const ref = doc(getDb(), "users", uid, "account_keys", "default");
    await runTransaction(getDb(), async (transaction) => {
      const snap = await transaction.get(ref);
      if (!snap.exists()) {
        throw new Error("Account keys document missing.");
      }
      const current = snap.data() as AccountKeysDocument;
      const updated = await updater(current);
      transaction.set(ref, updated);
    });
  }

  async setAccountKeys(docVal: AccountKeysDocument): Promise<void> {
    const uid = this.getUid();
    const ref = doc(getDb(), "users", uid, "account_keys", "default");
    await setDoc(ref, docVal);
  }

  async getKeystoreEntry(ledgerId: string): Promise<KeystoreEntry | null> {
    const uid = this.getUid();
    const ref = doc(getDb(), "users", uid, "keystore", ledgerId);
    const snap = await getDoc(ref);
    if (!snap.exists()) return null;
    return snap.data() as KeystoreEntry;
  }

  async setKeystoreEntry(ledgerId: string, entry: KeystoreEntry): Promise<void> {
    const uid = this.getUid();
    const ref = doc(getDb(), "users", uid, "keystore", ledgerId);
    await setDoc(ref, entry);
  }

  async setKeystoreArchivedStatus(docId: string, isArchived: boolean): Promise<void> {
    const uid = this.getUid();
    const ref = doc(getDb(), "users", uid, "keystore", docId);
    await updateDoc(ref, { isArchived });
  }

  async getPendingDevice(deviceId: string): Promise<PendingDevice | null> {
    const uid = this.getUid();
    const ref = doc(getDb(), "users", uid, "pending_devices", deviceId);
    const snap = await getDoc(ref);
    if (!snap.exists()) return null;
    return snap.data() as PendingDevice;
  }

  async setPendingDevice(deviceId: string, data: PendingDevice): Promise<void> {
    const uid = this.getUid();
    const ref = doc(getDb(), "users", uid, "pending_devices", deviceId);
    await setDoc(ref, data);
  }

  async transactApproveDevice(
    accountUpdater: (current: AccountKeysDocument) => AccountKeysDocument | Promise<AccountKeysDocument>,
    pendingDeviceId: string,
    pendingUpdate: Partial<PendingDevice>
  ): Promise<void> {
    const uid = this.getUid();
    const accountKeysRef = doc(getDb(), "users", uid, "account_keys", "default");
    const pendingRef = doc(getDb(), "users", uid, "pending_devices", pendingDeviceId);

    await runTransaction(getDb(), async (transaction) => {
      const snap = await transaction.get(accountKeysRef);
      if (!snap.exists()) {
        throw new Error("Account keys missing.");
      }
      const current = snap.data() as AccountKeysDocument;
      const updated = await accountUpdater(current);
      
      transaction.set(accountKeysRef, updated);
      transaction.update(pendingRef, pendingUpdate as any);
    });
  }

  subscribePendingDevices(
    onUpdate: (devices: PendingDevice[]) => void
  ): () => void {
    const uid = this.getUid();
    const q = query(
      collection(getDb(), "users", uid, "pending_devices"),
      where("status", "==", "pending")
    );
    return onSnapshot(q, (snap) => {
      const devices = snap.docs.map(d => d.data() as PendingDevice);
      onUpdate(devices);
    });
  }

  subscribePendingDevice(
    deviceId: string,
    onUpdate: (device: PendingDevice | null) => void
  ): () => void {
    const uid = this.getUid();
    const ref = doc(getDb(), "users", uid, "pending_devices", deviceId);
    return onSnapshot(ref, (snap) => {
      if (!snap.exists()) {
        onUpdate(null);
      } else {
        onUpdate(snap.data() as PendingDevice);
      }
    });
  }

  subscribeAccountKeys(
    onUpdate: (docVal: AccountKeysDocument | null) => void
  ): () => void {
    const uid = this.getUid();
    const ref = doc(getDb(), "users", uid, "account_keys", "default");
    return onSnapshot(ref, (snap) => {
      if (!snap.exists()) {
        onUpdate(null);
      } else {
        onUpdate(snap.data() as AccountKeysDocument);
      }
    });
  }

  subscribeKeystore(
    onUpdate: (entries: KeystoreEntry[]) => void
  ): () => void {
    const uid = this.getUid();
    const ref = collection(getDb(), "users", uid, "keystore");
    return onSnapshot(ref, (snap) => {
      const entries = snap.docs.map(d => d.data() as KeystoreEntry);
      onUpdate(entries);
    });
  }

  async deletePendingDevice(deviceId: string): Promise<void> {
    const uid = this.getUid();
    const ref = doc(getDb(), "users", uid, "pending_devices", deviceId);
    await deleteDoc(ref);
  }

  async resetRemoteStore(): Promise<void> {
    const uid = this.getUid();
    const keystoreRef = collection(getDb(), "users", uid, "keystore");
    const snap = await getDocs(keystoreRef);
    const batch = writeBatch(getDb());
    snap.docs.forEach(d => batch.delete(d.ref));
    batch.delete(doc(getDb(), "users", uid, "account_keys", "default"));
    await batch.commit();
  }
}
