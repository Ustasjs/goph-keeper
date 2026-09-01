package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ustasjs/goph-keeper/internal/client/crypt"
	"github.com/ustasjs/goph-keeper/internal/client/payload"
	"github.com/ustasjs/goph-keeper/internal/client/remote"
	"github.com/ustasjs/goph-keeper/internal/client/store"
	"github.com/ustasjs/goph-keeper/internal/secret"
)

// Build information, set by main from ldflags.
var (
	buildVersion = "N/A"
	buildDate    = "N/A"
)

// SetBuildInfo passes the values injected at link time.
func SetBuildInfo(version, date string) {
	buildVersion, buildDate = version, date
}

// NewRootCmd builds the command tree.
func NewRootCmd(app *App) *cobra.Command {
	root := &cobra.Command{
		Use:   "gophkeeper",
		Short: "GophKeeper client: keep private data safe",
		Long: "GophKeeper keeps logins, texts, files and bank cards.\n" +
			"Data is encrypted on this machine, so the server never sees it.",
		SilenceUsage: true,
		// main prints errors, in one place.
		SilenceErrors: true,
	}
	root.SetOut(app.out)
	root.SetErr(app.out)

	root.AddCommand(
		registerCmd(app),
		loginCmd(app),
		logoutCmd(app),
		listCmd(app),
		getCmd(app),
		addCmd(app),
		deleteCmd(app),
		versionCmd(app),
	)
	return root
}

func versionCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show the version and build date of this binary",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			fmt.Fprintf(app.out, "Build version: %s\nBuild date: %s\n", buildVersion, buildDate)
			return nil
		},
	}
}

func registerCmd(app *App) *cobra.Command {
	var login string

	cmd := &cobra.Command{
		Use:   "register",
		Short: "Create an account on the server",
		Long: "Register asks for two passwords.\n" +
			"The account password opens the account on the server.\n" +
			"The master password encrypts the data and never leaves this machine.\n" +
			"If the master password is lost, the data cannot be restored.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			login, err := app.lineOr(login, "Login: ")
			if err != nil {
				return err
			}
			if login == "" {
				return errors.New("login cannot be empty")
			}

			password, err := app.password()
			if err != nil {
				return err
			}
			masterPassword, err := app.masterPassword()
			if err != nil {
				return err
			}
			if masterPassword == "" {
				return errors.New("master password cannot be empty")
			}

			session, err := newSession(login, masterPassword)
			if err != nil {
				return err
			}

			client, err := app.remoteClient()
			if err != nil {
				return err
			}
			bundle := remote.CryptoBundle{
				KEKSalt:      session.KEKSalt,
				KDFParams:    session.KDFParams,
				EncryptedDEK: session.EncryptedDEK,
			}
			if err := client.Register(cmd.Context(), login, password, bundle); err != nil {
				return err
			}
			if err := app.store.SaveSession(session); err != nil {
				return err
			}

			fmt.Fprintf(app.out, "Registered as %s\n", login)
			return nil
		},
	}
	cmd.Flags().StringVar(&login, "login", "", "account login")
	return cmd
}

// newSession builds the crypto material for a new account: a
// random data key, wrapped with a key made from the master
// password.
func newSession(login, masterPassword string) (store.Session, error) {
	salt, err := crypt.NewSalt()
	if err != nil {
		return store.Session{}, err
	}
	params := crypt.DefaultKDFParams()
	kek, err := crypt.DeriveKEK(masterPassword, salt, params)
	if err != nil {
		return store.Session{}, err
	}
	dek, err := crypt.NewDEK()
	if err != nil {
		return store.Session{}, err
	}
	wrappedDEK, err := crypt.WrapDEK(dek, kek)
	if err != nil {
		return store.Session{}, err
	}

	return store.Session{
		Login:        login,
		KEKSalt:      salt,
		KDFParams:    params,
		EncryptedDEK: wrappedDEK,
	}, nil
}

func loginCmd(app *App) *cobra.Command {
	var login string

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to the server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			login, err := app.lineOr(login, "Login: ")
			if err != nil {
				return err
			}
			password, err := app.password()
			if err != nil {
				return err
			}

			client, err := app.remoteClient()
			if err != nil {
				return err
			}
			bundle, err := client.Login(cmd.Context(), login, password)
			if err != nil {
				return err
			}

			if err := app.store.SaveSession(store.Session{
				Login:        login,
				KEKSalt:      bundle.KEKSalt,
				KDFParams:    bundle.KDFParams,
				EncryptedDEK: bundle.EncryptedDEK,
			}); err != nil {
				return err
			}

			fmt.Fprintf(app.out, "Logged in as %s\n", login)
			return nil
		},
	}
	cmd.Flags().StringVar(&login, "login", "", "account login")
	return cmd
}

func logoutCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Forget the token, the session and the local copy",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := app.store.Clear(); err != nil {
				return err
			}
			fmt.Fprintln(app.out, "Logged out")
			return nil
		},
	}
}

func listCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show all records",
		Long: "List shows names, types and metadata.\n" +
			"It needs no master password: only the content is encrypted.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			list, err := app.secrets(cmd.Context())
			if err != nil {
				return err
			}
			if len(list) == 0 {
				fmt.Fprintln(app.out, "No records yet. Add one with \"gophkeeper add\".")
				return nil
			}

			sort.Slice(list, func(i, j int) bool {
				return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name)
			})

			w := tabwriter.NewWriter(app.out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tTYPE\tMETADATA\tID")
			for _, rec := range list {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", rec.Name, rec.Type, rec.Metadata, rec.ID)
			}
			return w.Flush()
		},
	}
}

func getCmd(app *App) *cobra.Command {
	var reveal bool

	cmd := &cobra.Command{
		Use:   "get <id|name>",
		Short: "Show one record",
		Long: "Get asks for the master password and decrypts the record.\n" +
			"Passwords and card numbers are hidden unless --reveal is used.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			list, err := app.secrets(cmd.Context())
			if err != nil {
				return err
			}
			rec, err := find(list, args[0])
			if err != nil {
				return err
			}

			dek, err := app.dek()
			if err != nil {
				return err
			}
			content, err := open(rec, dek)
			if err != nil {
				return err
			}

			fmt.Fprintf(app.out, "name:     %s\ntype:     %s\n", rec.Name, rec.Type)
			if rec.Metadata != "" {
				fmt.Fprintf(app.out, "metadata: %s\n", rec.Metadata)
			}
			fmt.Fprintln(app.out, "---")
			fmt.Fprintln(app.out, payload.Format(content, reveal))
			return nil
		},
	}
	cmd.Flags().BoolVar(&reveal, "reveal", false, "show the hidden values")
	return cmd
}

func deleteCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id|name>",
		Short: "Delete a record",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			list, err := app.secrets(cmd.Context())
			if err != nil {
				return err
			}
			rec, err := find(list, args[0])
			if err != nil {
				return err
			}

			client, err := app.remoteClient()
			if err != nil {
				return err
			}
			if err := client.DeleteSecret(cmd.Context(), rec.ID); err != nil {
				return err
			}

			fmt.Fprintf(app.out, "Deleted %s\n", rec.Name)
			return nil
		},
	}
}

// addFlags are the values a user can pass to add instead of
// answering questions.
type addFlags struct {
	name     string
	metadata string
	login    string
	text     string
	file     string
	number   string
	holder   string
	expiry   string
}

func addCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new record",
	}
	cmd.AddCommand(
		addTypeCmd(app, secret.TypeLoginPassword, "login-password", "Add a login and password"),
		addTypeCmd(app, secret.TypeText, "text", "Add a text note"),
		addTypeCmd(app, secret.TypeBinary, "binary", "Add a file"),
		addTypeCmd(app, secret.TypeCard, "card", "Add a bank card"),
	)
	return cmd
}

func addTypeCmd(app *App, recordType secret.Type, use, short string) *cobra.Command {
	var f addFlags

	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			name, err := app.lineOr(f.name, "Name: ")
			if err != nil {
				return err
			}
			if name == "" {
				return errors.New("name cannot be empty")
			}

			content, err := app.readContent(recordType, &f)
			if err != nil {
				return err
			}

			dek, err := app.dek()
			if err != nil {
				return err
			}
			blob, err := seal(content, dek)
			if err != nil {
				return err
			}

			client, err := app.remoteClient()
			if err != nil {
				return err
			}
			id, err := client.CreateSecret(cmd.Context(), secret.NewSecret{
				Type:     recordType,
				Name:     name,
				Metadata: f.metadata,
				Payload:  blob,
			})
			if err != nil {
				return err
			}

			fmt.Fprintf(app.out, "Added %s (%s)\n", name, id)
			return nil
		},
	}

	cmd.Flags().StringVar(&f.name, "name", "", "record name, for example \"github\"")
	cmd.Flags().StringVar(&f.metadata, "metadata", "", "any note: site, bank, person")
	switch recordType {
	case secret.TypeLoginPassword:
		cmd.Flags().StringVar(&f.login, "login", "", "login to store")
	case secret.TypeText:
		cmd.Flags().StringVar(&f.text, "text", "", "text to store")
	case secret.TypeBinary:
		cmd.Flags().StringVar(&f.file, "file", "", "file to store")
	case secret.TypeCard:
		cmd.Flags().StringVar(&f.number, "number", "", "card number")
		cmd.Flags().StringVar(&f.holder, "holder", "", "card holder")
		cmd.Flags().StringVar(&f.expiry, "expiry", "", "expiry date, MM/YY")
	}
	return cmd
}

// readContent collects the secret values for one record type,
// asking for what the flags did not give.
func (a *App) readContent(recordType secret.Type, f *addFlags) (any, error) {
	switch recordType {
	case secret.TypeLoginPassword:
		login, err := a.lineOr(f.login, "Login to store: ")
		if err != nil {
			return nil, err
		}
		password, err := a.secretInput(envPassword, "Password to store: ")
		if err != nil {
			return nil, err
		}
		return &payload.LoginPassword{Login: login, Password: password}, nil

	case secret.TypeText:
		text, err := a.lineOr(f.text, "Text: ")
		if err != nil {
			return nil, err
		}
		return &payload.Text{Text: text}, nil

	case secret.TypeBinary:
		return a.readFile(f.file)

	case secret.TypeCard:
		return a.readCard(f)

	default:
		return nil, fmt.Errorf("unknown record type %q", recordType)
	}
}

func (a *App) readFile(path string) (any, error) {
	path, err := a.lineOr(path, "Path to file: ")
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, errors.New("file path cannot be empty")
	}

	// Check the size before reading: a huge file would not fit
	// one gRPC message anyway.
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if info.Size() > payload.MaxSize {
		return nil, fmt.Errorf("%w: %s is %d bytes, limit is %d",
			payload.ErrTooLarge, path, info.Size(), payload.MaxSize)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return &payload.Binary{Filename: filepath.Base(path), Data: data}, nil
}

func (a *App) readCard(f *addFlags) (any, error) {
	number, err := a.lineOr(f.number, "Card number: ")
	if err != nil {
		return nil, err
	}
	holder, err := a.lineOr(f.holder, "Card holder: ")
	if err != nil {
		return nil, err
	}
	expiry, err := a.lineOr(f.expiry, "Expiry (MM/YY): ")
	if err != nil {
		return nil, err
	}
	cvv, err := a.secretInput(envPassword, "CVV: ")
	if err != nil {
		return nil, err
	}
	return &payload.Card{Number: number, Holder: holder, Expiry: expiry, CVV: cvv}, nil
}
