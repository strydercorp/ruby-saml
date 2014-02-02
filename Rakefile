require 'rubygems'
require 'spec/rake/spectask'
require 'bundler/gem_tasks'

Spec::Rake::SpecTask.new('spec') do |t|
  t.spec_files = FileList['spec/**/*_spec.rb']
end

task :default => :spec
