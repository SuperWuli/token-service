package scopes

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/entql"
	"github.com/samber/lo"

	"github.com/looplj/axonhub/internal/contexts"
	"github.com/looplj/axonhub/internal/ent"
	"github.com/looplj/axonhub/internal/ent/privacy"
	"github.com/looplj/axonhub/internal/ent/userproject"
)

type ProjectOwnedFilter interface {
	WhereProjectID(entql.IntP)
}

// userHasProjectScope checks if a user has the required scope for a specific project.
func userHasProjectScope(user *ent.User, projectID int, requiredScope ScopeSlug) bool {
	if user.IsOwner {
		return true
	}

	// Check if user has project membership with required scope
	membership, found := lo.Find(user.Edges.ProjectUsers, func(projectUser *ent.UserProject) bool {
		return projectUser.ProjectID == projectID
	})

	if !found {
		return false
	}

	if membership.IsOwner {
		return true
	}

	if hasScope(membership.Scopes, string(requiredScope)) {
		return true
	}

	for _, role := range user.Edges.Roles {
		if role.ProjectID != nil && *role.ProjectID == projectID {
			if hasScope(role.Scopes, string(requiredScope)) {
				return true
			}
		}
	}

	return false
}

// isProjectMember reports whether the user is a member of (or a system owner of) the given project.
func isProjectMember(user *ent.User, projectID int) bool {
	if user.IsOwner {
		return true
	}

	_, found := lo.Find(user.Edges.ProjectUsers, func(projectUser *ent.UserProject) bool {
		return projectUser.ProjectID == projectID
	})

	return found
}

// ProjectMemberReadRule allows a user to read the project referenced by the
// project ID in context when they are a member of it.
//
// The dedicated read_projects scope is system-only and can never be held by a
// project role, so without this rule non-owner project members are unable to
// read their own project node — which every project-scoped page resolves first
// via `node(id: Project) { ... }`. Reading is limited to the single project in
// context; broader project listing still requires the read_projects scope.
func ProjectMemberReadRule() privacy.QueryRule {
	return privacy.FilterFunc(func(ctx context.Context, q privacy.Filter) error {
		projectID, hasProjectID := contexts.GetProjectID(ctx)
		if !hasProjectID {
			return privacy.Skipf("Project ID not found in context")
		}

		currentUser, err := getUserFromContext(ctx)
		if err != nil {
			return privacy.Skipf("User not found in context")
		}

		pf, ok := q.(*ent.ProjectFilter)
		if !ok {
			return privacy.Skipf("Not a project query")
		}

		if !isProjectMember(currentUser, projectID) {
			return privacy.Skipf("User %d is not a member of project %d", currentUser.ID, projectID)
		}

		pf.WhereID(entql.IntEQ(projectID))

		return privacy.Allowf("User %d can read their project %d", currentUser.ID, projectID)
	})
}

// UserProjectMemberReadRule allows a user holding the required scope at project
// level (or system level) to read the users that belong to the project in
// context. The User entity has no project_id column, so scoping is applied
// through the project_users edge. This complements UserReadScopeRule, which
// only recognises the system-level scope.
func UserProjectMemberReadRule(requiredScope ScopeSlug) privacy.QueryRule {
	return privacy.FilterFunc(func(ctx context.Context, q privacy.Filter) error {
		projectID, hasProjectID := contexts.GetProjectID(ctx)
		if !hasProjectID {
			return privacy.Skipf("Project ID not found in context")
		}

		currentUser, err := getUserFromContext(ctx)
		if err != nil {
			return privacy.Skipf("User not found in context")
		}

		uf, ok := q.(*ent.UserFilter)
		if !ok {
			return privacy.Skipf("Not a user query")
		}

		if !HasSystemScope(currentUser, requiredScope) && !userHasProjectScope(currentUser, projectID, requiredScope) {
			return privacy.Skipf("User %d can not read users in project %d with scope %s", currentUser.ID, projectID, requiredScope)
		}

		uf.WhereHasProjectUsersWith(userproject.ProjectID(projectID))

		return privacy.Allowf("User %d can read users in project %d with scope %s", currentUser.ID, projectID, requiredScope)
	})
}

// UserProjectScopeReadRule allows users to query projects they are members of.
// It checks:
// 1. If user has global scope permission -> Allow all
// 2. If user is project member with required scope -> Filter by project membership.
func UserProjectScopeReadRule(requiredScope ScopeSlug) privacy.QueryRule {
	return privacy.FilterFunc(projectMemberQueryFilter(requiredScope))
}

func projectMemberQueryFilter(requiredScope ScopeSlug) func(ctx context.Context, q privacy.Filter) error {
	return func(ctx context.Context, q privacy.Filter) error {
		// Check if project ID is in context
		projectID, hasProjectID := contexts.GetProjectID(ctx)
		if !hasProjectID {
			return privacy.Skipf("Project ID not found in context")
		}

		currentUser, err := getUserFromContext(ctx)
		if err != nil {
			// Skip (not Deny) when no user is in context — mirrors
			// UserProjectScopeWriteRule's convention so non-user principals
			// (e.g. OpenAPI service account API keys) can fall through to
			// APIKeyProjectScopeReadRule instead of being hard-denied here.
			return privacy.Skipf("User not found in context")
		}

		switch q := q.(type) {
		case ProjectOwnedFilter:
			// Check if user has global scope permission or project scope permission.
			if !HasSystemScope(currentUser, requiredScope) && !userHasProjectScope(currentUser, projectID, requiredScope) {
				return privacy.Skipf("User %d can not query project %d with scope %s", currentUser.ID, projectID, requiredScope)
			}

			q.WhereProjectID(entql.IntEQ(projectID))

			return privacy.Allowf("User %d can query project %d with scope %s", currentUser.ID, projectID, requiredScope)
		case *ent.ProjectFilter:
			if !HasSystemScope(currentUser, requiredScope) && !userHasProjectScope(currentUser, projectID, requiredScope) {
				return privacy.Skipf("User %d can not query project %d with scope %s", currentUser.ID, projectID, requiredScope)
			}

			q.WhereID(entql.IntEQ(projectID))

			return privacy.Allowf("User %d can query project %d with scope %s", currentUser.ID, projectID, requiredScope)
		default:
			return privacy.Skipf("User %d can only query project %d with scope %s", currentUser.ID, projectID, requiredScope)
		}
	}
}

// UserProjectScopeWriteRule ensures users can only modify resources in projects they are members of.
func UserProjectScopeWriteRule(requiredScope ScopeSlug) privacy.MutationRule {
	return projectMemberMutationRule{requiredScope: requiredScope}
}

type ProjectOwnedMutation interface {
	ent.Mutation
	ProjectID() (r int, exists bool)
	WhereP(ps ...func(*sql.Selector))
}

type projectMemberMutationRule struct {
	requiredScope ScopeSlug
}

func (r projectMemberMutationRule) EvalMutation(ctx context.Context, m ent.Mutation) error {
	user, err := getUserFromContext(ctx)
	if err != nil {
		return privacy.Skipf("User not found in context")
	}

	if HasSystemScope(user, r.requiredScope) {
		return privacy.Allowf("User %d has system scope %s, allowing mutation", user.ID, r.requiredScope)
	}

	// For mutations, check project membership
	switch mutation := m.(type) {
	case ProjectOwnedMutation:
		projectID, hasProjectID := contexts.GetProjectID(ctx)
		if !hasProjectID {
			return privacy.Skipf("Project ID not found in context")
		}

		if !HasSystemScope(user, r.requiredScope) && !userHasProjectScope(user, projectID, r.requiredScope) {
			return privacy.Skipf("User %d can not modify resources in project %d with scope %s", user.ID, projectID, r.requiredScope)
		}

		switch mutation.Op() {
		case ent.OpCreate:
			mProjectID, ok := mutation.ProjectID()
			if !ok {
				return privacy.Skipf("Project ID not found")
			}

			if mProjectID != projectID {
				return privacy.Skipf("User %d can not create resources in project %d with scope %s", user.ID, mProjectID, r.requiredScope)
			}

			return privacy.Allowf("User %d can create resources in project %d", user.ID, mProjectID)
		case ent.OpUpdateOne, ent.OpDeleteOne:
			mutation.WhereP(func(s *sql.Selector) {
				s.Where(sql.EQ("project_id", projectID))
			})

			return privacy.Allowf("User %d can modify resources in project %d", user.ID, projectID)
		case ent.OpUpdate, ent.OpDelete:
			mutation.WhereP(func(s *sql.Selector) {
				s.Where(sql.EQ("project_id", projectID))
			})

			return privacy.Allowf("User %d can modify resources in project %d", user.ID, projectID)
		default:
			return privacy.Denyf("Unsupported operation %s", mutation.Op())
		}
	case *ent.ProjectMutation:
		// Check if user has global scope permission
		if HasSystemScope(user, r.requiredScope) {
			return privacy.Allowf("User %d can create project", user.ID)
		}

		if mutation.Op().Is(ent.OpCreate) {
			return privacy.Skipf("User %d can not create project", user.ID)
		}

		mProjectID, mProjectIDExists := mutation.ID()
		if !mProjectIDExists {
			return privacy.Skipf("Project ID not found")
		}

		if userHasProjectScope(user, mProjectID, r.requiredScope) {
			return privacy.Allowf("User %d can modify project %d", user.ID, mProjectID)
		}

		return privacy.Skipf("User %d can not modify project %d", user.ID, mProjectID)
	default:
		return privacy.Skipf("Not a project-related mutation")
	}
}
