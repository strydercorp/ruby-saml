require 'rubygems'
require 'spec/rake/spectask'
require 'bundler/gem_tasks'

Spec::Rake::SpecTask.new('spec') do |t|
  t.spec_files = FileList['spec/**/*_spec.rb']
end

task :default => :spec

namespace :vagrant do
  desc 'run tests in an ubuntu 12.04 vagrant vm'
  task :spec do
    sh 'vagrant ssh -c "cd /vagrant; bundle check || bundle install"'
    sh 'vagrant ssh -c "cd /vagrant; bundle exec rake spec"'
  end
end
