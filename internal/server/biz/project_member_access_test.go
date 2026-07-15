package biz

import (
	"context"
	"testing"

	"entgo.io/ent/dialect"
	"github.com/stretchr/testify/require"

	"github.com/looplj/axonhub/internal/authz"
	"github.com/looplj/axonhub/internal/contexts"
	"github.com/looplj/axonhub/internal/ent/enttest"
	"github.com/looplj/axonhub/internal/ent/role"
	"github.com/looplj/axonhub/internal/ent/user"
)

// TestProjectMemberResourceAccess is a regression test for non-owner project
// members: with a project-level role (read_users) they must be able to read
// their own project node and the project's users, while staying scoped to that
// project. read_projects is system-only, so this path is not covered by the
// unit rules in internal/scopes.
func TestProjectMemberResourceAccess(t *testing.T) {
	client := enttest.Open(t, dialect.SQLite, "file:repro?mode=memory&_fk=0")
	defer client.Close()

	bypass := authz.WithTestBypass(context.Background())

	proj := client.Project.Create().SetName("hermes").SaveX(bypass)
	otherProj := client.Project.Create().SetName("other").SaveX(bypass)

	devRole := client.Role.Create().
		SetName("Developer").
		SetLevel(role.LevelProject).
		SetProjectID(proj.ID).
		SetScopes([]string{"read_users", "read_api_keys", "write_api_keys", "read_requests"}).
		SaveX(bypass)

	u := client.User.Create().
		SetEmail("yangcan@doowintech.com").
		SetPassword("x").
		SetIsOwner(false).
		SetScopes([]string{}).
		SaveX(bypass)

	// A second member of the same project, plus a user only in another project.
	peer := client.User.Create().SetEmail("peer@doowintech.com").SetPassword("x").SaveX(bypass)
	outsider := client.User.Create().SetEmail("outsider@doowintech.com").SetPassword("x").SaveX(bypass)

	client.UserProject.Create().SetProjectID(proj.ID).SetUserID(u.ID).SetIsOwner(false).SetScopes([]string{}).SaveX(bypass)
	client.UserProject.Create().SetProjectID(proj.ID).SetUserID(peer.ID).SetIsOwner(false).SetScopes([]string{}).SaveX(bypass)
	client.UserProject.Create().SetProjectID(otherProj.ID).SetUserID(outsider.ID).SetIsOwner(false).SetScopes([]string{}).SaveX(bypass)

	client.User.UpdateOne(u).AddRoles(devRole).SaveX(bypass)

	full := client.User.Query().
		Where(user.IDEQ(u.ID)).
		WithRoles().
		WithProjectUsers().
		OnlyX(bypass)

	// Real request context: user + X-Project-ID (no bypass).
	ctx := contexts.WithProjectID(contexts.WithUser(context.Background(), full), proj.ID)

	t.Run("can read own project node", func(t *testing.T) {
		got, err := client.Project.Get(ctx, proj.ID)
		require.NoError(t, err)
		require.Equal(t, proj.ID, got.ID)
	})

	t.Run("cannot read a project they are not a member of", func(t *testing.T) {
		ctxOther := contexts.WithProjectID(contexts.WithUser(context.Background(), full), otherProj.ID)
		_, err := client.Project.Get(ctxOther, otherProj.ID)
		require.Error(t, err)
	})

	t.Run("can read users of the project, scoped to members", func(t *testing.T) {
		users, err := client.User.Query().All(ctx)
		require.NoError(t, err)

		emails := make(map[string]bool)
		for _, us := range users {
			emails[us.Email] = true
		}
		require.True(t, emails["yangcan@doowintech.com"], "should see self")
		require.True(t, emails["peer@doowintech.com"], "should see project peer")
		require.False(t, emails["outsider@doowintech.com"], "must NOT see users of other projects")
	})
}
