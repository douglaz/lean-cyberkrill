/-
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
-/
import Cli

namespace Cyberkrill

/-- Shared connection settings. Omitting the directory never probes the home directory. -/
structure RpcFlags where
  url : String := "http://127.0.0.1:8332"
  bitcoinDir : Option String := none
  user : Option String := none
  password : Option String := none
  deriving BEq

namespace RpcFlags

/-- Reuse on Core command groups only; offline commands have no RPC flags. -/
def flags : Array Cli.Flag := #[
  ⟨none, "rpc-url", "Bitcoin Core RPC URL (default http://127.0.0.1:8332)", String⟩,
  ⟨none, "bitcoin-dir", "Explicit directory containing .cookie; conflicts with credentials", String⟩,
  ⟨none, "rpc-user", "RPC username; requires a password for authentication", String⟩,
  ⟨none, "rpc-password", "RPC password; requires a username for authentication", String⟩]

/-- Extract and validate the common group from a command that registers `flags`. -/
def ofParsed (p : Cli.Parsed) : Except String RpcFlags := do
  let value := fun name => (p.flag? name).map (·.value)
  let dir := value "bitcoin-dir"
  let user := value "rpc-user"
  let password := value "rpc-password"
  if dir.isSome && (user.isSome || password.isSome) then
    throw "rpcFlagConflict: bitcoin-dir conflicts with rpc-user or rpc-password"
  return { url := (value "rpc-url").getD "http://127.0.0.1:8332", bitcoinDir := dir, user, password }

/-- In-process parser for the reusable group, without registering a command handler. -/
def parse (args : List String) : Except String RpcFlags := do
  let command := Cli.Cmd.mk "rpc-connection" none "Core connection settings"
    (flags := flags) (run := fun _ => pure 0)
  let (_, parsed) ← (command.parse args).mapError (fun _ => "invalidRpcFlags")
  ofParsed parsed

end RpcFlags
end Cyberkrill
