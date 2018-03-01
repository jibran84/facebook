class User < ApplicationRecord
  has_one :profile #when only one, then it's singular. if has_many it's plural
  has_many :status_updates
  has_many :memberships
  has_many :groups, through: :memberships
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable
end
