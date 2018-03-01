class HomeController < ApplicationController
  skip_before_action :authenticate_user!

  def index
    @latest_profile = Profile.last
    @status_update = StatusUpdate.new
    @status_updates = StatusUpdate.reverse_chron_order
  end
end
