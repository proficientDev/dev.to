require "rails_helper"

RSpec.describe UserPolicy, type: :policy do
  subject { described_class.new(user, other_user) }

  let(:other_user) { create(:user) }

  context "when user is not signed-in" do
    let(:user) { nil }

    it { within_block_is_expected.to raise_error(Pundit::NotAuthorizedError) }
  end

  context "when user is signed-in" do
    let(:user) { other_user }

    permitted_actions = %i[
      edit update onboarding_update join_org dashboard_show remove_identity destroy
    ]

    it { is_expected.to permit_actions(permitted_actions) }

    context "with banned status" do
      before { user.add_role_synchronously(:banned) }

      it { is_expected.to forbid_actions(%i[join_org moderation_routes]) }
    end
  end

  context "when user is trusted" do
    let(:user) { create(:user, :trusted) }

    it { is_expected.to permit_actions(%i[moderation_routes]) }
  end

  context "when user is not trusted" do
    let(:user) { create(:user) }

    it { is_expected.to forbid_actions(%i[moderation_routes]) }
  end

  context "when the user is an admin" do
    let(:user) { create(:user, :admin) }

    it { is_expected.to permit_actions(%i[moderation_routes]) }
  end

  context "when the user is a super admin" do
    let(:user) { create(:user, :super_admin) }

    it { is_expected.to permit_actions(%i[moderation_routes]) }
  end
end
