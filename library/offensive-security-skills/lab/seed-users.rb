# GDK BOLA/IDOR lab — user + token seeding (Rails runner)
# Run from the gitlab checkout:  cd ~/Desktop/beg-bounty/gdk/gitlab && bundle exec rails runner ../seed-users.rb
# Idempotent for users; always mints a fresh api-scoped PAT per run.
# Writes tokens to ~/Desktop/beg-bounty/lab-users.json for the API harness.

require 'json'

PW = 'Researcher!2026'
USERS = {
  'alice' => 'alice@lab.local',  # attacker identity
  'bob'   => 'bob@lab.local',    # victim identity
  'carol' => 'carol@lab.local'   # third-party identity
}

out = {}
USERS.each do |uname, email|
  u = User.find_by(username: uname)
  unless u
    u = User.new(username: uname, email: email, name: uname.capitalize,
                 password: PW, password_confirmation: PW)
    u.skip_confirmation!
    u.save!
    puts "created user #{uname} (id=#{u.id})"
  else
    puts "exists  user #{uname} (id=#{u.id})"
  end

  pat = u.personal_access_tokens.create!(
    name: "lab-#{Time.now.to_i}",
    scopes: ['api'],
    expires_at: 60.days.from_now
  )
  out[uname] = { 'id' => u.id, 'username' => uname, 'token' => pat.token }
  puts "  minted PAT for #{uname}"
end

path = File.expand_path('~/Desktop/beg-bounty/lab-users.json')
File.write(path, JSON.pretty_generate(out))
puts "WROTE #{path}"
