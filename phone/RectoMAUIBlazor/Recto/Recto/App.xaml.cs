namespace Recto;

public partial class App : Application
{
    public App()
    {
        InitializeComponent();
    }

    protected override Window CreateWindow(IActivationState? activationState)
    {
        var window = new Window(new MainPage()) { Title = "Recto" };

#if WINDOWS
        // Set explicit dimensions + position on Windows so MAUI Blazor
        // doesn't open as a small default-sized window. Phone-shaped
        // viewport for parity with the iOS / Android target experience.
        window.Width = 1400;
        window.Height = 900;
        window.X = 100;
        window.Y = 50;
#endif

        return window;
    }
}
