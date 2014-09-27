require 'fileutils'

directory 'gen'

task :default => :build

desc 'Build'
task :build => 'gen' do
  Dir.chdir 'vendor' do
    sh 'rake'
  end
  
  Dir.chdir('gen') do
    sh 'cmake ..'
    sh 'make'
  end
end

desc 'Run the test.'
task :test => 'gen' do
  Dir.chdir 'vendor' do
    sh 'rake devtool'
  end
  
  Dir.chdir('gen') do
    sh 'cmake -D IS_TEST=true ..'
    sh 'make'
    
    Dir.chdir('test') do
      FileUtils.rm_rf 'tmp'
      FileUtils.mkdir_p 'tmp'
      sh './spec_bin --reporter=spec'
    end
  end
end

desc 'Clean'
task :clean => 'gen' do
  Dir.chdir('gen') do
    sh 'make clean'
  end
end

desc 'Rebuild'
task :rebuild => 'gen' do
  Dir.chdir('gen') do
    sh 'make clean all'
  end
end

desc 'Distclean'
task :distclean do
  FileUtils.rm_rf 'gen'
  if ENV['r'] == 'true' then
    Dir.chdir 'vendor' do
      sh 'rake distclean'
    end
  end
end
