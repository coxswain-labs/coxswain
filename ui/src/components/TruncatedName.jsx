/**
 * Middle-ellipsised name.
 *
 * Kubernetes pod names share a deployment prefix across replicas and differ
 * only in the tail (ReplicaSet hash + pod suffix). Truncating the end would
 * make replicas indistinguishable, so we pin the last `tailLen` characters and
 * ellipsise the head: `coxswain-shared-pr…c-95jn6`. The full name is on the
 * `title` tooltip; copy it verbatim with the adjacent CopyButton.
 */
export function TruncatedName({ name, tailLen = 7 }) {
  const split = name.length > tailLen + 1;
  const head  = split ? name.slice(0, name.length - tailLen) : name;
  const tail  = split ? name.slice(name.length - tailLen) : '';
  return (
    <span class="trunc-name" title={name}>
      <span class="trunc-head">{head}</span>
      {tail && <span class="trunc-tail">{tail}</span>}
    </span>
  );
}
