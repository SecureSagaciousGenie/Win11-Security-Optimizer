<#
    Optimizer.ps1  --  Windows 11 Security Optimizer (WPF GUI)
    ----------------------------------------------------------
    Everything the user does happens in this window:
      Dashboard | Security | Debloat | Investigate (DFIR) | Startup | Restore & Logs

    This file is the PRESENTATION layer. All real work lives in SecurityCore.ps1,
    which this script dot-sources. Scans run in a background runspace so the UI
    stays responsive; state-changing actions run on confirm and are all reversible.

    Launch via Start.bat (self-elevates). Direct:
      powershell -NoProfile -ExecutionPolicy Bypass -STA -File .\src\Optimizer.ps1

    Validate headlessly:
      powershell -NoProfile -ExecutionPolicy Bypass -STA -File .\src\Optimizer.ps1 -SelfTest
#>
[CmdletBinding()]
param(
    [switch]$SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---- Locate & load the backend ---------------------------------------------
$script:ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$script:CorePath  = Join-Path $script:ScriptDir 'SecurityCore.ps1'
if (-not (Test-Path $script:CorePath)) { throw "SecurityCore.ps1 not found next to Optimizer.ps1 ($script:CorePath)" }
. $script:CorePath

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml | Out-Null

# ---- Strongly-typed row models (reliable WPF binding) ----------------------
if (-not ('W11SO.AppRow' -as [type])) {
Add-Type -ReferencedAssemblies System.ComponentModel -TypeDefinition @"
using System.ComponentModel;
namespace W11SO {
  public class NotifyBase : INotifyPropertyChanged {
    public event PropertyChangedEventHandler PropertyChanged;
    protected void OnChanged(string n){ var h=PropertyChanged; if(h!=null) h(this, new PropertyChangedEventArgs(n)); }
  }
  public class AppRow : NotifyBase {
    private bool _sel;
    public bool Selected { get{return _sel;} set{ _sel=value; OnChanged("Selected"); } }
    public string Name {get;set;}
    public string Publisher {get;set;}
    public string Category {get;set;}
    public string Version {get;set;}
    public string Description {get;set;}
    public string AppxName {get;set;}
    public string ReinstallNote {get;set;}
  }
  public class StartupRow : NotifyBase {
    private bool _en;
    public bool Enabled { get{return _en;} set{ _en=value; OnChanged("Enabled"); } }
    public string Name {get;set;}
    public string Kind {get;set;}
    public string Publisher {get;set;}
    public string SignedText {get;set;}
    public string Command {get;set;}
    public string Location {get;set;}
    public string Scope {get;set;}
  }
}
"@
}

# ============================================================================
#  XAML  (dark modern theme; single-quoted here-string = no interpolation)
# ============================================================================
$script:Xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Windows 11 Security Optimizer" Height="730" Width="1150"
        WindowStartupLocation="CenterScreen" Background="#0E1117"
        FontFamily="Segoe UI" FontSize="13">
  <Window.Resources>
    <!-- palette -->
    <SolidColorBrush x:Key="Bg"      Color="#0E1117"/>
    <SolidColorBrush x:Key="Panel"   Color="#161B22"/>
    <SolidColorBrush x:Key="Panel2"  Color="#1C2230"/>
    <SolidColorBrush x:Key="Stroke"  Color="#2A3140"/>
    <SolidColorBrush x:Key="Text"    Color="#E6EDF3"/>
    <SolidColorBrush x:Key="Muted"   Color="#8B949E"/>
    <SolidColorBrush x:Key="Accent"  Color="#2F81F7"/>
    <SolidColorBrush x:Key="Good"    Color="#3FB950"/>
    <SolidColorBrush x:Key="Warn"    Color="#D29922"/>
    <SolidColorBrush x:Key="Bad"     Color="#F85149"/>

    <Style TargetType="TextBlock">
      <Setter Property="Foreground" Value="{StaticResource Text}"/>
    </Style>

    <!-- nav button -->
    <Style x:Key="Nav" TargetType="Button">
      <Setter Property="Height" Value="46"/>
      <Setter Property="Foreground" Value="{StaticResource Muted}"/>
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="HorizontalContentAlignment" Value="Left"/>
      <Setter Property="Padding" Value="18,0,0,0"/>
      <Setter Property="FontSize" Value="14"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="b" Background="{TemplateBinding Background}" CornerRadius="8" Margin="10,2,10,2">
              <Grid>
                <Border x:Name="bar" Width="3" HorizontalAlignment="Left" Background="{StaticResource Accent}"
                        CornerRadius="2" Margin="2,8,0,8" Visibility="Collapsed"/>
                <ContentPresenter VerticalAlignment="Center" Margin="{TemplateBinding Padding}"/>
              </Grid>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="b" Property="Background" Value="#1C2230"/>
                <Setter Property="Foreground" Value="{StaticResource Text}"/>
              </Trigger>
              <Trigger Property="Tag" Value="active">
                <Setter TargetName="b" Property="Background" Value="#1C2230"/>
                <Setter TargetName="bar" Property="Visibility" Value="Visible"/>
                <Setter Property="Foreground" Value="{StaticResource Text}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- primary button -->
    <Style x:Key="Primary" TargetType="Button">
      <Setter Property="Background" Value="{StaticResource Accent}"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="16,8,16,8"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="b" Background="{TemplateBinding Background}" CornerRadius="7" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#4C9AFF"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter TargetName="b" Property="Background" Value="#30363D"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- ghost button -->
    <Style x:Key="Ghost" TargetType="Button" BasedOn="{StaticResource Primary}">
      <Setter Property="Background" Value="#21262D"/>
      <Setter Property="Foreground" Value="{StaticResource Text}"/>
    </Style>

    <Style TargetType="ListView">
      <Setter Property="Background" Value="{StaticResource Panel}"/>
      <Setter Property="BorderBrush" Value="{StaticResource Stroke}"/>
      <Setter Property="Foreground" Value="{StaticResource Text}"/>
    </Style>
    <Style TargetType="GridViewColumnHeader">
      <Setter Property="Background" Value="#1C2230"/>
      <Setter Property="Foreground" Value="{StaticResource Muted}"/>
      <Setter Property="BorderBrush" Value="{StaticResource Stroke}"/>
      <Setter Property="Padding" Value="10,8,10,8"/>
      <Setter Property="HorizontalContentAlignment" Value="Left"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style TargetType="ListViewItem">
      <Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Padding" Value="4"/>
      <Setter Property="BorderBrush" Value="{StaticResource Stroke}"/>
      <Setter Property="BorderThickness" Value="0,0,0,1"/>
      <Style.Triggers>
        <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="#243043"/></Trigger>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#1C2230"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style TargetType="CheckBox">
      <Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>
    <Style TargetType="ScrollBar"><Setter Property="Background" Value="#0E1117"/></Style>
  </Window.Resources>

  <Grid>
    <Grid.ColumnDefinitions>
      <ColumnDefinition Width="220"/>
      <ColumnDefinition Width="*"/>
    </Grid.ColumnDefinitions>

    <!-- ================= LEFT NAV ================= -->
    <Border Grid.Column="0" Background="#0B0E14" BorderBrush="{StaticResource Stroke}" BorderThickness="0,0,1,0">
      <DockPanel>
        <StackPanel DockPanel.Dock="Top" Margin="18,20,18,10">
          <TextBlock Text="Windows 11" Foreground="{StaticResource Muted}" FontSize="12"/>
          <TextBlock Text="Security Optimizer" FontSize="18" FontWeight="Bold"/>
          <Border Height="1" Background="{StaticResource Stroke}" Margin="0,14,0,6"/>
        </StackPanel>
        <StackPanel DockPanel.Dock="Bottom" Margin="18,10,18,16">
          <Border x:Name="AdminBadge" Background="#2A1E12" CornerRadius="6" Padding="10,7" Margin="0,0,0,8">
            <TextBlock x:Name="AdminText" Text="Not elevated" Foreground="{StaticResource Warn}" FontSize="11.5" TextWrapping="Wrap"/>
          </Border>
          <TextBlock x:Name="VersionText" Text="v1.0.0" Foreground="{StaticResource Muted}" FontSize="11"/>
        </StackPanel>
        <StackPanel x:Name="NavPanel" Margin="0,6,0,0">
          <Button x:Name="NavDashboard"  Style="{StaticResource Nav}" Content="  Dashboard"/>
          <Button x:Name="NavSecurity"   Style="{StaticResource Nav}" Content="  Security"/>
          <Button x:Name="NavDebloat"    Style="{StaticResource Nav}" Content="  Debloat"/>
          <Button x:Name="NavInvestigate" Style="{StaticResource Nav}" Content="  Investigate"/>
          <Button x:Name="NavStartup"    Style="{StaticResource Nav}" Content="  Startup"/>
          <Button x:Name="NavRestore"    Style="{StaticResource Nav}" Content="  Restore &amp; Logs"/>
        </StackPanel>
      </DockPanel>
    </Border>

    <!-- ================= RIGHT CONTENT ================= -->
    <Grid Grid.Column="1">
      <Grid.RowDefinitions>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="*"/>
        <RowDefinition Height="Auto"/>
      </Grid.RowDefinitions>

      <!-- header -->
      <Grid Grid.Row="0" Margin="26,22,26,8">
        <StackPanel>
          <TextBlock x:Name="PageTitle" Text="Dashboard" FontSize="22" FontWeight="Bold"/>
          <TextBlock x:Name="PageSubtitle" Text="Overview of this PC's security posture." Foreground="{StaticResource Muted}" Margin="0,2,0,0"/>
        </StackPanel>
        <Button x:Name="BtnRefresh" Style="{StaticResource Ghost}" Content="Refresh" HorizontalAlignment="Right" VerticalAlignment="Top"/>
      </Grid>

      <!-- pages host -->
      <Grid Grid.Row="1" Margin="26,6,26,6">

        <!-- DASHBOARD -->
        <Grid x:Name="PageDashboard">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <UniformGrid Grid.Row="0" Columns="4" Margin="0,0,0,14">
            <Border Background="{StaticResource Panel}" CornerRadius="10" Margin="0,0,8,0" Padding="16">
              <StackPanel>
                <TextBlock Text="SECURITY SCORE" Foreground="{StaticResource Muted}" FontSize="11"/>
                <TextBlock x:Name="CardScore" Text="--" FontSize="34" FontWeight="Bold"/>
                <TextBlock x:Name="CardGrade" Text="Run a scan" Foreground="{StaticResource Muted}" FontSize="12"/>
              </StackPanel>
            </Border>
            <Border Background="{StaticResource Panel}" CornerRadius="10" Margin="8,0,8,0" Padding="16">
              <StackPanel>
                <TextBlock Text="HARDENING ISSUES" Foreground="{StaticResource Muted}" FontSize="11"/>
                <TextBlock x:Name="CardIssues" Text="--" FontSize="34" FontWeight="Bold" Foreground="{StaticResource Warn}"/>
                <TextBlock Text="warnings + failures" Foreground="{StaticResource Muted}" FontSize="12"/>
              </StackPanel>
            </Border>
            <Border Background="{StaticResource Panel}" CornerRadius="10" Margin="8,0,8,0" Padding="16">
              <StackPanel>
                <TextBlock Text="INVESTIGATION" Foreground="{StaticResource Muted}" FontSize="11"/>
                <TextBlock x:Name="CardDfir" Text="--" FontSize="34" FontWeight="Bold" Foreground="{StaticResource Bad}"/>
                <TextBlock Text="items to review" Foreground="{StaticResource Muted}" FontSize="12"/>
              </StackPanel>
            </Border>
            <Border Background="{StaticResource Panel}" CornerRadius="10" Margin="8,0,0,0" Padding="16">
              <StackPanel>
                <TextBlock Text="REMOVABLE BLOAT" Foreground="{StaticResource Muted}" FontSize="11"/>
                <TextBlock x:Name="CardBloat" Text="--" FontSize="34" FontWeight="Bold" Foreground="{StaticResource Accent}"/>
                <TextBlock Text="apps installed" Foreground="{StaticResource Muted}" FontSize="12"/>
              </StackPanel>
            </Border>
          </UniformGrid>
          <Border Grid.Row="1" Background="{StaticResource Panel}" CornerRadius="10" Padding="20">
            <StackPanel>
              <TextBlock Text="Welcome" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,8"/>
              <TextBlock TextWrapping="Wrap" Foreground="{StaticResource Muted}" LineHeight="20">
                This tool scans your Windows 11 PC and helps you (1) harden security settings, (2) remove
                pre-installed bloat you don't use, (3) investigate whether anything looks compromised, and
                (4) manage which apps launch at startup.<LineBreak/><LineBreak/>
                Nothing on your PC is changed until you explicitly approve it. Before the first change this
                tool creates a System Restore point and writes a rollback script, so every change can be undone.
                Click "Run Full Scan" to begin.
              </TextBlock>
              <Button x:Name="BtnFullScan" Style="{StaticResource Primary}" Content="Run Full Scan" HorizontalAlignment="Left" Margin="0,16,0,0"/>
            </StackPanel>
          </Border>
        </Grid>

        <!-- SECURITY -->
        <Grid x:Name="PageSecurity" Visibility="Collapsed">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,12">
            <Button x:Name="BtnSecScan" Style="{StaticResource Primary}" Content="Scan Security"/>
            <Button x:Name="BtnSecFixSafe" Style="{StaticResource Ghost}" Content="Apply Recommended Fixes" Margin="10,0,0,0"/>
            <CheckBox x:Name="ChkHighRisk" Content="Include high-risk fixes" Margin="16,0,0,0"/>
          </StackPanel>
          <ListView x:Name="SecList" Grid.Row="1">
            <ListView.View>
              <GridView>
                <GridViewColumn Header="" Width="34">
                  <GridViewColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding StatusIcon}" Foreground="{Binding StatusBrush}" FontWeight="Bold" HorizontalAlignment="Center"/></DataTemplate></GridViewColumn.CellTemplate>
                </GridViewColumn>
                <GridViewColumn Header="Check" Width="260" DisplayMemberBinding="{Binding Name}"/>
                <GridViewColumn Header="Severity" Width="80" DisplayMemberBinding="{Binding Severity}"/>
                <GridViewColumn Header="Current" Width="190" DisplayMemberBinding="{Binding Observed}"/>
                <GridViewColumn Header="Advice" Width="250" DisplayMemberBinding="{Binding Advice}"/>
                <GridViewColumn Header="Action" Width="90">
                  <GridViewColumn.CellTemplate><DataTemplate>
                    <Button Content="Fix" Tag="{Binding Id}" Padding="12,4" Visibility="{Binding FixVis}"
                            Background="#21262D" Foreground="#E6EDF3" BorderThickness="0" Cursor="Hand"/>
                  </DataTemplate></GridViewColumn.CellTemplate>
                </GridViewColumn>
              </GridView>
            </ListView.View>
          </ListView>
        </Grid>

        <!-- DEBLOAT -->
        <Grid x:Name="PageDebloat" Visibility="Collapsed">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
          <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,12">
            <Button x:Name="BtnBloatScan" Style="{StaticResource Primary}" Content="Scan Installed Apps"/>
            <Button x:Name="BtnBloatSelectRec" Style="{StaticResource Ghost}" Content="Select Recommended" Margin="10,0,0,0"/>
            <Button x:Name="BtnBloatClear" Style="{StaticResource Ghost}" Content="Clear" Margin="10,0,0,0"/>
          </StackPanel>
          <ListView x:Name="BloatList" Grid.Row="1">
            <ListView.View>
              <GridView>
                <GridViewColumn Header="Remove" Width="64">
                  <GridViewColumn.CellTemplate><DataTemplate><CheckBox IsChecked="{Binding Selected, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}" HorizontalAlignment="Center"/></DataTemplate></GridViewColumn.CellTemplate>
                </GridViewColumn>
                <GridViewColumn Header="App" Width="220" DisplayMemberBinding="{Binding Name}"/>
                <GridViewColumn Header="Category" Width="110" DisplayMemberBinding="{Binding Category}"/>
                <GridViewColumn Header="What it is / why remove it" Width="430" >
                  <GridViewColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding Description}" TextWrapping="Wrap" Foreground="#8B949E"/></DataTemplate></GridViewColumn.CellTemplate>
                </GridViewColumn>
              </GridView>
            </ListView.View>
          </ListView>
          <DockPanel Grid.Row="2" Margin="0,12,0,0">
            <TextBlock x:Name="BloatStatus" Text="" Foreground="{StaticResource Muted}" VerticalAlignment="Center"/>
            <Button x:Name="BtnBloatRemove" Style="{StaticResource Primary}" Content="Remove Selected" HorizontalAlignment="Right" DockPanel.Dock="Right"/>
          </DockPanel>
        </Grid>

        <!-- INVESTIGATE / DFIR -->
        <Grid x:Name="PageInvestigate" Visibility="Collapsed">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,12">
            <Button x:Name="BtnDfirScan" Style="{StaticResource Primary}" Content="Investigate This PC"/>
            <Button x:Name="BtnDeepScan" Style="{StaticResource Ghost}" Content="+ Deep Scan (processes &amp; logs)" Margin="10,0,0,0"/>
            <Button x:Name="BtnProScan" Style="{StaticResource Ghost}" Content="+ Pro Tools (Hayabusa / Chainsaw)" Margin="10,0,0,0"/>
            <TextBlock x:Name="DfirSummary" Text="Checks for hidden admins, backdoors, remote access, and tampering." Foreground="{StaticResource Muted}" VerticalAlignment="Center" Margin="14,0,0,0"/>
          </StackPanel>
          <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto">
            <ItemsControl x:Name="DfirList">
              <ItemsControl.ItemTemplate>
                <DataTemplate>
                  <Border Background="{StaticResource Panel}" CornerRadius="10" Padding="16" Margin="0,0,0,10" BorderBrush="{Binding AccentBrush}" BorderThickness="1,1,1,1">
                    <StackPanel>
                      <DockPanel>
                        <Border Background="{Binding AccentBrush}" CornerRadius="4" Padding="7,2" DockPanel.Dock="Left" Margin="0,0,10,0">
                          <TextBlock Text="{Binding Severity}" Foreground="White" FontSize="11" FontWeight="Bold"/>
                        </Border>
                        <TextBlock Text="{Binding Title}" FontSize="15" FontWeight="SemiBold" VerticalAlignment="Center"/>
                      </DockPanel>
                      <TextBlock Text="{Binding What}" TextWrapping="Wrap" Margin="0,10,0,0" Foreground="{StaticResource Text}"/>
                      <TextBlock Text="{Binding Why}" TextWrapping="Wrap" Margin="0,8,0,0" Foreground="{StaticResource Muted}" Visibility="{Binding WhyVis}"/>
                      <Border Background="#10151D" CornerRadius="6" Padding="10" Margin="0,10,0,0" Visibility="{Binding DoVis}">
                        <StackPanel>
                          <TextBlock Text="What to do" Foreground="{StaticResource Accent}" FontWeight="SemiBold" FontSize="12"/>
                          <TextBlock Text="{Binding WhatToDo}" TextWrapping="Wrap" Margin="0,4,0,0" Foreground="{StaticResource Text}"/>
                        </StackPanel>
                      </Border>
                    </StackPanel>
                  </Border>
                </DataTemplate>
              </ItemsControl.ItemTemplate>
            </ItemsControl>
          </ScrollViewer>
        </Grid>

        <!-- STARTUP -->
        <Grid x:Name="PageStartup" Visibility="Collapsed">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,12">
            <Button x:Name="BtnStartupScan" Style="{StaticResource Primary}" Content="List Startup Apps"/>
            <TextBlock Text="Toggle the switch to enable/disable (reversible)." Foreground="{StaticResource Muted}" VerticalAlignment="Center" Margin="14,0,0,0"/>
          </StackPanel>
          <ListView x:Name="StartupListView" Grid.Row="1">
            <ListView.View>
              <GridView>
                <GridViewColumn Header="On" Width="60">
                  <GridViewColumn.CellTemplate><DataTemplate><CheckBox IsChecked="{Binding Enabled, Mode=TwoWay}" Tag="{Binding Name}" HorizontalAlignment="Center"/></DataTemplate></GridViewColumn.CellTemplate>
                </GridViewColumn>
                <GridViewColumn Header="Name" Width="200" DisplayMemberBinding="{Binding Name}"/>
                <GridViewColumn Header="Publisher" Width="200" DisplayMemberBinding="{Binding Publisher}"/>
                <GridViewColumn Header="Signed" Width="90" DisplayMemberBinding="{Binding SignedText}"/>
                <GridViewColumn Header="Type" Width="120" DisplayMemberBinding="{Binding Kind}"/>
                <GridViewColumn Header="Command" Width="300" DisplayMemberBinding="{Binding Command}"/>
              </GridView>
            </ListView.View>
          </ListView>
        </Grid>

        <!-- RESTORE & LOGS -->
        <Grid x:Name="PageRestore" Visibility="Collapsed">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <StackPanel Grid.Row="0" Margin="0,0,0,12">
            <TextBlock Text="Safety &amp; rollback" FontSize="15" FontWeight="SemiBold"/>
            <TextBlock TextWrapping="Wrap" Foreground="{StaticResource Muted}" Margin="0,6,0,0">
              A System Restore point is created automatically before the first change in a session. Every change is
              also written to a rollback script you can run to undo it. Use the buttons below to open those files.
            </TextBlock>
            <StackPanel Orientation="Horizontal" Margin="0,12,0,0">
              <Button x:Name="BtnOpenData" Style="{StaticResource Ghost}" Content="Open Backup Folder"/>
              <Button x:Name="BtnOpenRollback" Style="{StaticResource Ghost}" Content="Open Rollback Script" Margin="10,0,0,0"/>
              <Button x:Name="BtnMakeRestore" Style="{StaticResource Ghost}" Content="Create Restore Point Now" Margin="10,0,0,0"/>
              <Button x:Name="BtnRemoveTools" Style="{StaticResource Ghost}" Content="Remove Downloaded Tools" Margin="10,0,0,0"/>
            </StackPanel>
          </StackPanel>
          <Border Grid.Row="1" Background="#0B0E14" BorderBrush="{StaticResource Stroke}" BorderThickness="1" CornerRadius="8">
            <ScrollViewer x:Name="LogScroller" VerticalScrollBarVisibility="Auto" Padding="12">
              <TextBlock x:Name="LogView" FontFamily="Consolas" FontSize="12" Foreground="#9FB1C1" TextWrapping="Wrap"/>
            </ScrollViewer>
          </Border>
        </Grid>

      </Grid>

      <!-- status bar -->
      <Border Grid.Row="2" Background="#0B0E14" BorderBrush="{StaticResource Stroke}" BorderThickness="0,1,0,0" Padding="26,8">
        <DockPanel>
          <TextBlock x:Name="StatusText" Text="Ready." Foreground="{StaticResource Muted}"/>
          <ProgressBar x:Name="Busy" Width="160" Height="6" IsIndeterminate="True" Visibility="Collapsed"
                       DockPanel.Dock="Right" Background="#161B22" Foreground="{StaticResource Accent}" BorderThickness="0"/>
        </DockPanel>
      </Border>
    </Grid>
  </Grid>
</Window>
'@

# ============================================================================
#  BUILD WINDOW
# ============================================================================
function New-OptimizerWindow {
    $reader = New-Object System.Xml.XmlNodeReader ([xml]$script:Xaml)
    $win = [Windows.Markup.XamlReader]::Load($reader)

    # Index named elements into a hashtable for easy access.
    $ui = @{}
    $names = @(
        'NavDashboard','NavSecurity','NavDebloat','NavInvestigate','NavStartup','NavRestore',
        'PageTitle','PageSubtitle','BtnRefresh','AdminBadge','AdminText','VersionText',
        'PageDashboard','PageSecurity','PageDebloat','PageInvestigate','PageStartup','PageRestore',
        'CardScore','CardGrade','CardIssues','CardDfir','CardBloat','BtnFullScan',
        'BtnSecScan','BtnSecFixSafe','ChkHighRisk','SecList',
        'BtnBloatScan','BtnBloatSelectRec','BtnBloatClear','BloatList','BloatStatus','BtnBloatRemove',
        'BtnDfirScan','BtnDeepScan','BtnProScan','DfirSummary','DfirList',
        'BtnStartupScan','StartupListView',
        'BtnOpenData','BtnOpenRollback','BtnMakeRestore','BtnRemoveTools','LogView','LogScroller',
        'StatusText','Busy'
    )
    foreach ($n in $names) { $ui[$n] = $win.FindName($n) }
    return @{ Window=$win; UI=$ui }
}

# ============================================================================
#  BACKGROUND RUNSPACE HELPER  (keeps UI responsive during scans)
# ============================================================================
function Invoke-Background {
    <#
      Runs $Work (a scriptblock that returns data) on a background runspace that
      has SecurityCore.ps1 loaded, then calls $OnDone with the result on the UI
      thread via the Dispatcher.

      Pass inputs to $Work via -Vars @{ Name = value } (they become plain
      variables inside the runspace). Do NOT use $using: - it does not work in a
      manually-created runspace. $Work may report progress by calling
      & $Report $msg  (a helper injected into the runspace) or by setting
      $SharedState.Status = $msg directly.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Work,
        [Parameter(Mandatory)]$OnDone,
        [string]$Status = 'Working...',
        [hashtable]$Vars = @{}
    )
    $script:UIRef.UI.StatusText.Text = $Status
    $script:UIRef.UI.Busy.Visibility = 'Visible'

    # Thread-safe channel so the background work can push live status to the UI.
    $shared = [hashtable]::Synchronized(@{ Status = $Status })

    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'
    $rs.ThreadOptions  = 'ReuseThread'
    $rs.Open()
    $rs.SessionStateProxy.SetVariable('CorePath', $script:CorePath)
    $rs.SessionStateProxy.SetVariable('WorkBody', $Work)
    $rs.SessionStateProxy.SetVariable('SharedState', $shared)
    foreach ($k in $Vars.Keys) { $rs.SessionStateProxy.SetVariable($k, $Vars[$k]) }

    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript({
        . $CorePath
        Initialize-Core | Out-Null
        # Progress helper available to $WorkBody as $Report.
        $Report = { param($m) try { $SharedState.Status = $m } catch { } }
        Set-Variable -Name Report -Value $Report -Scope Global
        & $WorkBody
    })

    $handle = $ps.BeginInvoke()

    # Poll for completion on a DispatcherTimer (UI thread) so results marshal safely.
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(150)
    $timer.Add_Tick({
        # live progress
        try { if ($shared.Status) { $script:UIRef.UI.StatusText.Text = $shared.Status } } catch { }
        if ($handle.IsCompleted) {
            $timer.Stop()
            $result = $null; $err = $null
            try { $result = $ps.EndInvoke($handle) } catch { $err = $_ }
            try { $ps.Dispose() } catch { }
            try { $rs.Close(); $rs.Dispose() } catch { }
            $script:UIRef.UI.Busy.Visibility = 'Collapsed'
            $script:UIRef.UI.StatusText.Text = 'Ready.'
            if ($err) {
                $script:UIRef.UI.StatusText.Text = "Error: $($err.Exception.Message)"
            } else {
                & $OnDone $result
            }
        }
    }.GetNewClosure())
    $timer.Start()
}

# convenience: run a quick synchronous action with busy indicator
function Set-Busy { param([string]$Text='Working...',[bool]$On=$true)
    $script:UIRef.UI.StatusText.Text = if($On){$Text}else{'Ready.'}
    $script:UIRef.UI.Busy.Visibility = if($On){'Visible'}else{'Collapsed'}
}

# ============================================================================
#  NAVIGATION
# ============================================================================
$script:Pages = @{
    Dashboard   = @{ Page='PageDashboard';   Nav='NavDashboard';   Title='Dashboard';   Sub="Overview of this PC's security posture." }
    Security    = @{ Page='PageSecurity';    Nav='NavSecurity';    Title='Security';    Sub='Audit and harden Windows security settings. Each fix is reversible.' }
    Debloat     = @{ Page='PageDebloat';     Nav='NavDebloat';     Title='Debloat';     Sub='Remove pre-installed apps you do not use. You pick each one; all are reinstallable.' }
    Investigate = @{ Page='PageInvestigate'; Nav='NavInvestigate'; Title='Investigate';  Sub='Check this PC for signs of compromise, in plain English. "Deep Scan" also hunts running processes and event logs.' }
    Startup     = @{ Page='PageStartup';     Nav='NavStartup';     Title='Startup';     Sub='See what launches at boot and turn items off (reversible).' }
    Restore     = @{ Page='PageRestore';     Nav='NavRestore';     Title='Restore & Logs'; Sub='Backups, rollback, and the activity log for this session.' }
}

function Show-Page {
    param([string]$Key)
    foreach ($k in $script:Pages.Keys) {
        $p = $script:Pages[$k]
        $script:UIRef.UI[$p.Page].Visibility = if ($k -eq $Key) { 'Visible' } else { 'Collapsed' }
        $script:UIRef.UI[$p.Nav].Tag = if ($k -eq $Key) { 'active' } else { $null }
    }
    $script:UIRef.UI.PageTitle.Text    = $script:Pages[$Key].Title
    $script:UIRef.UI.PageSubtitle.Text = $script:Pages[$Key].Sub
    if ($Key -eq 'Restore') { Update-LogView }
}

# ============================================================================
#  PRESENTATION HELPERS  (attach display props to backend objects)
# ============================================================================
$script:SevBrush = @{
    'Critical'='#F85149'; 'High'='#F85149'; 'Medium'='#D29922'; 'Low'='#6E7681'; 'Info'='#2F81F7'
}
function Get-Brush { param([string]$Hex) New-Object Windows.Media.SolidColorBrush ([Windows.Media.ColorConverter]::ConvertFromString($Hex)) }

function ConvertTo-SecRow {
    param($f)
    $icon = switch ($f.Status) { 'Pass'{[char]0x2714} 'Fail'{[char]0x2716} 'Warning'{'!'} 'Error'{'?'} default{[char]0x2139} }
    $brushHex = switch ($f.Status) { 'Pass'{'#3FB950'} 'Fail'{'#F85149'} 'Warning'{'#D29922'} default{'#2F81F7'} }
    $f | Add-Member -NotePropertyName StatusIcon  -NotePropertyValue ([string]$icon) -Force
    $f | Add-Member -NotePropertyName StatusBrush -NotePropertyValue (Get-Brush $brushHex) -Force
    $f | Add-Member -NotePropertyName FixVis -NotePropertyValue $(if ($f.Fixable -and $f.Status -ne 'Pass') { 'Visible' } else { 'Collapsed' }) -Force
    return $f
}

function ConvertTo-DfirCard {
    param($f)
    $hex = $script:SevBrush[$f.Severity]
    if ($f.Status -eq 'Clean') { $hex = '#2A3140' }
    $f | Add-Member -NotePropertyName AccentBrush -NotePropertyValue (Get-Brush $hex) -Force
    $f | Add-Member -NotePropertyName WhyVis -NotePropertyValue $(if ($f.Why) { 'Visible' } else { 'Collapsed' }) -Force
    $f | Add-Member -NotePropertyName DoVis  -NotePropertyValue $(if ($f.WhatToDo) { 'Visible' } else { 'Collapsed' }) -Force
    return $f
}

function Update-LogView {
    $tail = Get-CoreLogTail -Lines 300
    $script:UIRef.UI.LogView.Text = ($tail -join "`r`n")
    try { $script:UIRef.UI.LogScroller.ScrollToEnd() } catch { }
}

# ============================================================================
#  ACTIONS: SECURITY
# ============================================================================
function Start-SecurityScan {
    Invoke-Background -Status 'Scanning security settings...' -Work {
        $f = Invoke-SecurityScan
        [pscustomobject]@{ Findings=$f; Score=(Get-SecurityScore $f) }
    } -OnDone {
        param($res)
        $script:State.Security = $res.Findings
        $rows = $res.Findings | ForEach-Object { ConvertTo-SecRow $_ }
        $script:UIRef.UI.SecList.ItemsSource = @($rows)
        $sc = $res.Score
        $script:UIRef.UI.CardScore.Text  = "$($sc.Score)"
        $script:UIRef.UI.CardGrade.Text  = "Grade $($sc.Grade)  -  $($sc.Pass) ok / $($sc.Warn) warn / $($sc.Fail) fail"
        $script:UIRef.UI.CardIssues.Text = "$($sc.Warn + $sc.Fail)"
        $script:UIRef.UI.StatusText.Text = "Security scan complete: score $($sc.Score)/100."
    }
}

function Invoke-SecFix {
    param([string]$Id)
    $finding = $script:State.Security | Where-Object { $_.Id -eq $Id } | Select-Object -First 1
    if (-not $finding) { return }
    $msg = "Apply this fix?`n`n$($finding.Name)`n`nCurrent: $($finding.Observed)`nTarget: $($finding.Expected)"
    if ($finding.RiskTier -eq 'HighRisk') { $msg += "`n`nWARNING: High-impact change. Make sure you understand the effect." }
    $msg += "`n`nA System Restore point is created before the first change, and this is reversible via the rollback script."
    $r = [System.Windows.MessageBox]::Show($msg, 'Confirm fix', 'YesNo', $(if($finding.RiskTier -eq 'HighRisk'){'Warning'}else{'Question'}))
    if ($r -ne 'Yes') { return }

    if (-not (Test-IsAdmin)) {
        [System.Windows.MessageBox]::Show("This change needs administrator rights. Please relaunch via Start.bat (it will prompt for elevation).", 'Administrator required', 'OK', 'Warning') | Out-Null
        return
    }
    Set-Busy -Text "Applying $($finding.Name)..."
    $res = Invoke-SecurityFix -Id $Id
    Set-Busy -On $false
    if ($res.Success) {
        $script:UIRef.UI.StatusText.Text = "Applied: $($finding.Name)."
        Start-SecurityScan
    } else {
        [System.Windows.MessageBox]::Show("Could not apply fix:`n$($res.Message)", 'Fix failed', 'OK', 'Error') | Out-Null
    }
}

function Invoke-SecApplyAllSafe {
    if (-not (Test-IsAdmin)) {
        [System.Windows.MessageBox]::Show("Applying fixes needs administrator rights. Relaunch via Start.bat.", 'Administrator required', 'OK', 'Warning') | Out-Null
        return
    }
    $incHigh = [bool]$script:UIRef.UI.ChkHighRisk.IsChecked
    $targets = $script:State.Security | Where-Object {
        $_.Fixable -and $_.Status -ne 'Pass' -and $_.RiskTier -ne 'AuditOnly' -and
        ($_.RiskTier -ne 'HighRisk' -or $incHigh)
    }
    if (-not $targets -or @($targets).Count -eq 0) {
        [System.Windows.MessageBox]::Show('Nothing to apply with the current options.', 'Nothing to do', 'OK', 'Information') | Out-Null
        return
    }
    # Group by tier so the user sees exactly what is Safe vs the more impactful
    # "Elevated"/"High-risk" standard-hardening items (SMBv1, LLMNR, ASR Block, RDP NLA).
    $safe     = @($targets | Where-Object { $_.RiskTier -eq 'Safe' })
    $elevated = @($targets | Where-Object { $_.RiskTier -eq 'Elevated' })
    $high     = @($targets | Where-Object { $_.RiskTier -eq 'HighRisk' })
    $sb = New-Object System.Text.StringBuilder
    if ($safe.Count)     { [void]$sb.AppendLine("SAFE (low-risk):");          $safe     | ForEach-Object { [void]$sb.AppendLine("   - $($_.Name)") } }
    if ($elevated.Count) { [void]$sb.AppendLine("");[void]$sb.AppendLine("ELEVATED (standard hardening, may affect some setups):"); $elevated | ForEach-Object { [void]$sb.AppendLine("   - $($_.Name)") } }
    if ($high.Count)     { [void]$sb.AppendLine("");[void]$sb.AppendLine("HIGH-RISK:"); $high | ForEach-Object { [void]$sb.AppendLine("   - $($_.Name)") } }
    $r = [System.Windows.MessageBox]::Show(("Apply these {0} fix(es)? They are grouped by risk tier below.`n`n{1}`nA System Restore point is created first; every change is reversible via the rollback script." -f @($targets).Count, $sb.ToString()), 'Confirm batch', 'YesNo', 'Question')
    if ($r -ne 'Yes') { return }

    # State-changing actions run SYNCHRONOUSLY on the main thread, because the
    # rollback/backup/restore-point state lives in this runspace's loaded Core.
    # (Background runspaces are used only for read-only scans.)
    $ids = @($targets | ForEach-Object { $_.Id })
    Set-Busy -Text 'Applying fixes...'
    $ok = 0
    foreach ($id in $ids) {
        $r = Invoke-SecurityFix -Id $id
        if ($r.Success) { $ok++ }
    }
    Set-Busy -On $false
    $script:UIRef.UI.StatusText.Text = "Applied $ok of $($ids.Count) fixes."
    Start-SecurityScan
}


# ============================================================================
#  VISUAL TREE HELPER
# ============================================================================
function Find-VisualChildren {
    param([Parameter(Mandatory)]$Parent, [Parameter(Mandatory)][type]$Type)
    $results = New-Object System.Collections.ArrayList
    $count = [System.Windows.Media.VisualTreeHelper]::GetChildrenCount($Parent)
    for ($i = 0; $i -lt $count; $i++) {
        $child = [System.Windows.Media.VisualTreeHelper]::GetChild($Parent, $i)
        if ($child -and $child.GetType() -eq $Type) { [void]$results.Add($child) }
        if ($child) { foreach ($g in (Find-VisualChildren -Parent $child -Type $Type)) { [void]$results.Add($g) } }
    }
    return $results
}

# ============================================================================
#  ACTIONS: DEBLOAT
# ============================================================================
function Start-BloatScan {
    Invoke-Background -Status 'Scanning installed apps...' -Work { Get-DebloatInventory } -OnDone {
        param($inv)
        $rows = New-Object System.Collections.ObjectModel.ObservableCollection[object]
        foreach ($a in @($inv)) {
            $row = New-Object W11SO.AppRow
            $row.Selected=$false; $row.Name=$a.Name; $row.Publisher=$a.Publisher; $row.Category=$a.Category
            $row.Version=$a.Version; $row.Description=$a.Description; $row.AppxName=$a.PackageFullName
            $row.ReinstallNote=$a.ReinstallNote
            # keep the wildcard for removal + a 'Recommended' hint
            $row | Add-Member -NotePropertyName Wildcard -NotePropertyValue (Get-DebloatWildcard $a.Key) -Force
            $row | Add-Member -NotePropertyName Recommended -NotePropertyValue $a.Recommended -Force
            $rows.Add($row)
        }
        $script:State.Bloat = $rows
        $script:UIRef.UI.BloatList.ItemsSource = $rows
        $script:UIRef.UI.CardBloat.Text = "$($rows.Count)"
        $script:UIRef.UI.BloatStatus.Text = "$($rows.Count) removable app(s) found. Tick the ones to remove."
    }
}

# Resolve the catalog wildcard for a key (used for removal) without re-scanning.
function Get-DebloatWildcard { param([string]$Key)
    $c = Get-DebloatCatalog | Where-Object { $_.Key -eq $Key } | Select-Object -First 1
    if ($c) { return $c.AppxName } else { return $null }
}

function Invoke-BloatRemove {
    if (-not $script:State.Bloat) { return }
    $selected = @($script:State.Bloat | Where-Object { $_.Selected })
    if ($selected.Count -eq 0) {
        [System.Windows.MessageBox]::Show('No apps are ticked. Tick the apps you want to remove first.', 'Nothing selected', 'OK', 'Information') | Out-Null
        return
    }
    if (-not (Test-IsAdmin)) {
        [System.Windows.MessageBox]::Show("Removing apps needs administrator rights. Relaunch via Start.bat.", 'Administrator required', 'OK', 'Warning') | Out-Null
        return
    }
    $list = ($selected | ForEach-Object { " - $($_.Name)" }) -join "`n"
    $r = [System.Windows.MessageBox]::Show("Remove these $($selected.Count) app(s)?`n`n$list`n`nAll are reinstallable from the Microsoft Store. A restore point is created first and the removal is logged.", 'Confirm removal', 'YesNo', 'Question')
    if ($r -ne 'Yes') { return }

    Set-Busy -Text 'Removing selected apps...'
    $ok = 0; $fail = @()
    foreach ($app in $selected) {
        $wc = if ($app.Wildcard) { $app.Wildcard } else { $app.AppxName }
        $res = Remove-DebloatApp -AppxName $wc -FriendlyName $app.Name
        if ($res.Success) { $ok++ } else { $fail += "$($app.Name): $($res.Message)" }
    }
    Set-Busy -On $false
    $summary = "Removed $ok of $($selected.Count) app(s)."
    if ($fail.Count -gt 0) { $summary += "`n`nNot removed:`n" + ($fail -join "`n") }
    [System.Windows.MessageBox]::Show($summary, 'Debloat complete', 'OK', 'Information') | Out-Null
    Start-BloatScan
}

# ============================================================================
#  ACTIONS: DFIR
# ============================================================================
function Start-DfirScan {
    param([switch]$Deep)
    $statusMsg = if ($Deep) { 'Running deep scan (processes + event logs)...' } else { 'Investigating this PC...' }
    Invoke-Background -Status $statusMsg -Vars @{ DeepFlag = [bool]$Deep } -Work {
        $f = Invoke-DfirTriage
        if ($DeepFlag) {
            foreach ($x in @(Invoke-DeepScan)) { $f += $x }
        }
        [pscustomobject]@{ Findings=$f; Summary=(Get-DfirSummary $f) }
    } -OnDone {
        param($res)
        $cards = $res.Findings | ForEach-Object { ConvertTo-DfirCard $_ }
        # Alerts/Reviews first, then clean
        $order = @{ 'Alert'=0; 'Review'=1; 'Info'=2; 'Clean'=3 }
        $sorted = $cards | Sort-Object @{ Expression={ $order[$_.Status] } }, @{ Expression={ $_.Severity } }
        $script:UIRef.UI.DfirList.ItemsSource = @($sorted)
        $s = $res.Summary
        $script:UIRef.UI.CardDfir.Text = "$($s.Alerts + $s.Reviews)"
        $script:UIRef.UI.DfirSummary.Text = "$($s.Alerts) alert(s), $($s.Reviews) to review, $($s.Clean) clean."
        $script:UIRef.UI.StatusText.Text = 'Investigation complete.'
    }
}

# ============================================================================
#  ACTIONS: PRO TOOLS  (opt-in external DFIR tools - Hayabusa / Chainsaw)
# ============================================================================

$script:ConsentXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Download external tool" Height="620" Width="640"
        WindowStartupLocation="CenterOwner" Background="#0E1117"
        FontFamily="Segoe UI" FontSize="13" ResizeMode="NoResize" WindowStyle="SingleBorderWindow">
  <Grid Margin="0">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <Border Grid.Row="0" Background="#0B1B34" Padding="22,18">
      <StackPanel>
        <TextBlock x:Name="CTitle" Text="Download a third-party tool" FontSize="19" FontWeight="Bold" Foreground="#E6EDF3"/>
        <TextBlock x:Name="CSubtitle" Text="This tool is not part of the optimizer. You are choosing to download it." Foreground="#9FB3D1" Margin="0,3,0,0"/>
      </StackPanel>
    </Border>
    <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" Padding="22,16">
      <StackPanel>
        <Border Background="#161B22" CornerRadius="8" Padding="16" Margin="0,0,0,12">
          <StackPanel>
            <Grid Margin="0,0,0,6"><Grid.ColumnDefinitions><ColumnDefinition Width="120"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
              <TextBlock Grid.Column="0" Text="Tool" Foreground="#8B949E"/><TextBlock x:Name="CName" Grid.Column="1" Foreground="#E6EDF3" FontWeight="SemiBold"/></Grid>
            <Grid Margin="0,0,0,6"><Grid.ColumnDefinitions><ColumnDefinition Width="120"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
              <TextBlock Grid.Column="0" Text="Made by" Foreground="#8B949E"/><TextBlock x:Name="CVendor" Grid.Column="1" Foreground="#E6EDF3"/></Grid>
            <Grid Margin="0,0,0,6"><Grid.ColumnDefinitions><ColumnDefinition Width="120"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
              <TextBlock Grid.Column="0" Text="License" Foreground="#8B949E"/><TextBlock x:Name="CLicense" Grid.Column="1" Foreground="#D29922" FontWeight="SemiBold"/></Grid>
            <Grid Margin="0,0,0,6"><Grid.ColumnDefinitions><ColumnDefinition Width="120"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
              <TextBlock Grid.Column="0" Text="Version" Foreground="#8B949E"/><TextBlock x:Name="CVersion" Grid.Column="1" Foreground="#E6EDF3"/></Grid>
            <Grid Margin="0,0,0,6"><Grid.ColumnDefinitions><ColumnDefinition Width="120"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
              <TextBlock Grid.Column="0" Text="Download size" Foreground="#8B949E"/><TextBlock x:Name="CSize" Grid.Column="1" Foreground="#E6EDF3"/></Grid>
            <Grid Margin="0,0,0,6"><Grid.ColumnDefinitions><ColumnDefinition Width="120"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
              <TextBlock Grid.Column="0" Text="Source (official)" Foreground="#8B949E"/><TextBlock x:Name="CUrl" Grid.Column="1" Foreground="#2F81F7" TextWrapping="Wrap"/></Grid>
            <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="120"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
              <TextBlock Grid.Column="0" Text="Integrity" Foreground="#8B949E"/><TextBlock x:Name="CIntegrity" Grid.Column="1" Foreground="#E6EDF3" TextWrapping="Wrap"/></Grid>
          </StackPanel>
        </Border>
        <TextBlock x:Name="CDesc" TextWrapping="Wrap" Foreground="#C9D1D9" Margin="2,0,0,12" LineHeight="19"/>
        <Border Background="#2A1E12" CornerRadius="8" Padding="14" Margin="0,0,0,12">
          <StackPanel>
            <TextBlock Text="Please understand before continuing:" Foreground="#D29922" FontWeight="SemiBold" Margin="0,0,0,6"/>
            <TextBlock TextWrapping="Wrap" Foreground="#C9D1D9" LineHeight="19">
              - This downloads a separate program from the internet (the official GitHub release above) and runs it on your PC to read your Windows event logs.<LineBreak/>
              - It is licensed under its own license (shown above), NOT the optimizer's MIT license. The optimizer only runs it; it does not include or redistribute it.<LineBreak/>
              - It runs read-only against your logs. The optimizer refuses to install unless the download's SHA-256 matches a trusted hash (see "Integrity" above), but you are trusting the upstream project itself.<LineBreak/>
              - Some antivirus/EDR products flag security tools like these (they are "hacktools" by category). That does not necessarily mean they are malicious, but you should be comfortable with that.
            </TextBlock>
          </StackPanel>
        </Border>
        <CheckBox x:Name="CAccept" Foreground="#E6EDF3" Margin="2,0,0,0">
          <TextBlock TextWrapping="Wrap" Text="I understand this downloads and runs a third-party, separately-licensed tool from its official source, and I accept its license." Foreground="#E6EDF3"/>
        </CheckBox>
      </StackPanel>
    </ScrollViewer>
    <Border Grid.Row="2" Background="#0B0E14" BorderBrush="#2A3140" BorderThickness="0,1,0,0" Padding="22,14">
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="CCancel" Content="Cancel" Width="110" Height="36" Background="#21262D" Foreground="#E6EDF3" BorderThickness="0" Cursor="Hand" Margin="0,0,10,0"/>
        <Button x:Name="COk" Content="Download &amp; Run" Width="150" Height="36" Background="#2F81F7" Foreground="White" BorderThickness="0" Cursor="Hand" IsEnabled="False"/>
      </StackPanel>
    </Border>
  </Grid>
</Window>
'@

function Show-ConsentDialog {
    <# Resolves the release (network, metadata only), shows the consent window,
       and returns the resolution object if accepted, else $null. #>
    param([Parameter(Mandatory)][string]$Key)

    $tool = Get-ExternalTool -Key $Key
    Set-Busy -Text ("Checking latest {0} release..." -f $tool.Name)
    $res = $null; $err = $null
    try { $res = Resolve-ExternalToolRelease -Key $Key } catch { $err = $_.Exception.Message }
    Set-Busy -On $false
    if (-not $res) {
        [System.Windows.MessageBox]::Show("Could not reach the release server for $($tool.Name).`n`n$err`n`nCheck your internet connection and try again.", 'Could not resolve download', 'OK', 'Warning') | Out-Null
        return $null
    }

    $reader = New-Object System.Xml.XmlNodeReader ([xml]$script:ConsentXaml)
    $dlg = [Windows.Markup.XamlReader]::Load($reader)
    $dlg.Owner = $script:UIRef.Window
    $g = { param($n) $dlg.FindName($n) }

    (& $g 'CTitle').Text    = "Download $($res.Name)?"
    (& $g 'CName').Text      = $res.Name
    (& $g 'CVendor').Text    = $res.Vendor
    (& $g 'CLicense').Text   = $res.License
    (& $g 'CVersion').Text   = $res.Version
    (& $g 'CSize').Text       = ("{0} MB  ({1})" -f $res.SizeMB, $res.AssetName)
    (& $g 'CUrl').Text        = $res.DownloadUrl
    (& $g 'CDesc').Text       = $res.Summary

    # Integrity line + fail-closed guard. These tools run elevated, so if there is
    # no trusted hash (neither a project-pinned hash nor a GitHub-advertised
    # digest) we refuse the download outright rather than offer to run it anyway.
    $src = ''; try { $src = [string]$res.Sha256Source } catch { }
    $hasHash = $false; try { $hasHash = [bool]$res.Sha256Expected } catch { }
    $cInteg = & $g 'CIntegrity'
    if (-not $hasHash -or $src -eq 'none') {
        [System.Windows.MessageBox]::Show("$($tool.Name) cannot be installed: no trusted SHA-256 is available for this download (the project has no pinned hash for it and GitHub advertised no digest).`n`nBecause this tool runs with administrator rights, it will not be downloaded from an unverifiable source.", 'Download refused (no verifiable hash)', 'OK', 'Warning') | Out-Null
        return $null
    } elseif ($src -eq 'pinned') {
        $cInteg.Text = 'SHA-256 pinned & reviewed by this project (verified before running)'
        try { $cInteg.Foreground = '#3FB950' } catch { }
    } else {
        $cInteg.Text = ("SHA-256 from GitHub release digest (verified before running). Note: version {0} is newer than this project's reviewed version {1}." -f $res.Version, $res.PinnedVersion)
        try { $cInteg.Foreground = '#D29922' } catch { }
    }

    $accept = & $g 'CAccept'; $ok = & $g 'COk'; $cancel = & $g 'CCancel'
    $accept.Add_Checked({   $ok.IsEnabled = $true })
    $accept.Add_Unchecked({ $ok.IsEnabled = $false })
    $script:_consentResult = $false
    $ok.Add_Click({ $script:_consentResult = $true; $dlg.Close() }.GetNewClosure())
    $cancel.Add_Click({ $script:_consentResult = $false; $dlg.Close() }.GetNewClosure())

    [void]$dlg.ShowDialog()
    if ($script:_consentResult) { return $res }
    return $null
}

function Start-ProScan {
    param([Parameter(Mandatory)][string]$Key)
    $tool = Get-ExternalTool -Key $Key

    if (-not (Test-IsAdmin)) {
        [System.Windows.MessageBox]::Show("$($tool.Name) needs administrator rights to read the Windows Security log. Relaunch via Start.bat.", 'Administrator required', 'OK', 'Warning') | Out-Null
        return
    }

    # Prepare + lock the secure tools root up front. If a standard user pre-created
    # the ProgramData folder (or planted a binary in it) so it is not owned by
    # Administrators/SYSTEM, this deletes and recreates it - so the "already
    # installed?" check below cannot be tricked into skipping consent and running
    # attacker-planted content.
    try { [void](Initialize-SecureToolsRoot) }
    catch {
        [System.Windows.MessageBox]::Show("Could not secure the tools folder:`n$($_.Exception.Message)", 'Pro Tools blocked', 'OK', 'Error') | Out-Null
        return
    }

    # Already installed? Offer to reuse without re-consenting to a download.
    $installed = Test-ExternalToolInstalled -Key $Key
    $resolution = $null
    if (-not $installed) {
        $resolution = Show-ConsentDialog -Key $Key
        if (-not $resolution) { $script:UIRef.UI.StatusText.Text = 'Pro tool download cancelled.'; return }
    }

    # Download (if needed) + run + parse, all on a background runspace so the UI
    # stays responsive. Consent has already been captured on the UI thread; the
    # resolution object is passed in via -Vars. Progress flows through $Report
    # (injected into the runspace) -> $SharedState.Status -> the status bar.
    Invoke-Background -Status ("Running {0}..." -f $tool.Name) -Vars @{ ProKey = $Key; ProResolution = $resolution } -Work {
        # Install if not present (consent already given on UI thread when ProResolution is set).
        $exe = Test-ExternalToolInstalled -Key $ProKey
        if (-not $exe) {
            $inst = Install-ExternalTool -Key $ProKey -ConsentAccepted -Resolution $ProResolution -Progress $Report
            if (-not $inst.Success) { return [pscustomobject]@{ Error = $inst.Message; Findings=@() } }
            $exe = $inst.ExePath
        }
        $findings = Invoke-ExternalDfirScan -Key $ProKey -ExePath $exe -Progress $Report
        [pscustomobject]@{ Error=$null; Findings=$findings }
    } -OnDone {
        param($res)
        if ($res.Error) {
            [System.Windows.MessageBox]::Show("$($tool.Name) could not complete:`n$($res.Error)", 'Pro tool failed', 'OK', 'Error') | Out-Null
            return
        }
        # Merge the external findings INTO the current Investigate list (keep native ones).
        $existing = @()
        if ($script:UIRef.UI.DfirList.ItemsSource) { $existing = @($script:UIRef.UI.DfirList.ItemsSource) }
        $cards = $res.Findings | ForEach-Object { ConvertTo-DfirCard $_ }
        $combined = @($existing) + @($cards)
        $order = @{ 'Alert'=0; 'Review'=1; 'Info'=2; 'Clean'=3 }
        $sorted = $combined | Sort-Object @{ Expression={ $order[$_.Status] } }, @{ Expression={ $_.Severity } }
        $script:UIRef.UI.DfirList.ItemsSource = @($sorted)
        $alerts = @($combined | Where-Object { $_.Status -eq 'Alert' }).Count
        $reviews = @($combined | Where-Object { $_.Status -eq 'Review' }).Count
        $script:UIRef.UI.CardDfir.Text = "$($alerts + $reviews)"
        $script:UIRef.UI.DfirSummary.Text = "$($tool.Name) added $(@($cards).Count) result card(s)."
        $script:UIRef.UI.StatusText.Text = "$($tool.Name) scan complete."
    }
}

function Show-ProToolMenu {
    # Simple chooser: which pro tool to run.
    $msg = "Pro Tools run best-in-class open-source DFIR scanners against your event logs.`n`nThey are downloaded from their official GitHub release the first time (you'll see a consent screen with the license), then reused.`n`nChoose a tool:`n`n  YES  = Hayabusa (timeline threat hunter)`n  NO   = Chainsaw (Sigma rule hunter)`n  CANCEL = close"
    $r = [System.Windows.MessageBox]::Show($msg, 'Pro Tools (external, opt-in)', 'YesNoCancel', 'Question')
    switch ($r) {
        'Yes' { Start-ProScan -Key 'hayabusa' }
        'No'  { Start-ProScan -Key 'chainsaw' }
        default { }
    }
}
# ============================================================================
function Start-StartupScan {
    Invoke-Background -Status 'Listing startup apps...' -Work { Get-StartupItems } -OnDone {
        param($items)
        $rows = New-Object System.Collections.ObjectModel.ObservableCollection[object]
        foreach ($i in @($items)) {
            $row = New-Object W11SO.StartupRow
            $row.Enabled = [bool]$i.Enabled
            $row.Name=$i.Name; $row.Kind=$i.Type; $row.Publisher=$i.Publisher
            $row.SignedText = if ($i.Signed) { 'Signed' } else { 'UNSIGNED' }
            $row.Command=$i.Command; $row.Location=$i.Location; $row.Scope=$i.Scope
            # remember how to toggle it
            $row | Add-Member -NotePropertyName _Type -NotePropertyValue $i.Type -Force
            $row | Add-Member -NotePropertyName _ValueType -NotePropertyValue $(if ($i.PSObject.Properties.Name -contains 'ValueType') { $i.ValueType } else { 'String' }) -Force
            $rows.Add($row)
            $row.add_PropertyChanged({ param($snd,$e)
                if ($e.PropertyName -eq 'Enabled') { Invoke-StartupToggle -Row $snd }
            })
        }
        $script:State.Startup = $rows
        $script:State.StartupSuppress = $false
        $script:UIRef.UI.StartupListView.ItemsSource = $rows
        $script:UIRef.UI.StatusText.Text = "$($rows.Count) startup item(s)."
    }
}

function Invoke-StartupToggle {
    param($Row)
    if ($script:State.StartupSuppress) { return }
    if (-not (Test-IsAdmin)) {
        $script:State.StartupSuppress = $true; $Row.Enabled = (-not $Row.Enabled); $script:State.StartupSuppress = $false
        [System.Windows.MessageBox]::Show("Changing startup items needs administrator rights. Relaunch via Start.bat.", 'Administrator required', 'OK', 'Warning') | Out-Null
        return
    }
    $res = Set-StartupItemState -Type $Row._Type -Location $Row.Location -Name $Row.Name -Enable $Row.Enabled -Command $Row.Command -ValueType $Row._ValueType
    if ($res.Success) {
        $script:UIRef.UI.StatusText.Text = "$($Row.Name): $($res.Message)"
    } else {
        # revert the toggle visually
        $script:State.StartupSuppress = $true; $Row.Enabled = (-not $Row.Enabled); $script:State.StartupSuppress = $false
        [System.Windows.MessageBox]::Show("Could not change '$($Row.Name)':`n$($res.Message)", 'Failed', 'OK', 'Error') | Out-Null
    }
}

# ============================================================================
#  ACTIONS: FULL SCAN (dashboard)
# ============================================================================
function Start-FullScan {
    Start-SecurityScan
    Start-BloatScan
    Start-DfirScan
    Start-StartupScan
}

# ============================================================================
#  RESTORE & LOGS
# ============================================================================
function Open-DataFolder {
    $p = $script:Core.DataPath
    if ($p -and (Test-Path $p)) { Start-Process explorer.exe $p } 
}
function Open-RollbackScript {
    $p = $script:Core.RollbackFile
    if ($p -and (Test-Path $p)) { Start-Process notepad.exe $p }
    else { [System.Windows.MessageBox]::Show('No rollback script yet - it is created after your first change.', 'No rollback yet', 'OK', 'Information') | Out-Null }
}
function Invoke-MakeRestorePoint {
    if (-not (Test-IsAdmin)) { [System.Windows.MessageBox]::Show('Creating a restore point needs admin. Relaunch via Start.bat.','Administrator required','OK','Warning') | Out-Null; return }
    Set-Busy -Text 'Creating System Restore point...'
    $ok = New-SystemRestorePointOnce -Description 'Win11 Security Optimizer - manual'
    Set-Busy -On $false
    $msg = if ($ok) { 'System Restore point created (or already exists for this session).' } else { 'Could not create a restore point. System Protection may be off for the system drive.' }
    [System.Windows.MessageBox]::Show($msg, 'Restore point', 'OK', 'Information') | Out-Null
    Update-LogView
}

# ============================================================================
#  WIRE EVENTS
# ============================================================================
function Register-Handlers {
    $u = $script:UIRef.UI
    $u.NavDashboard.Add_Click({ Show-Page 'Dashboard' })
    $u.NavSecurity.Add_Click({ Show-Page 'Security' })
    $u.NavDebloat.Add_Click({ Show-Page 'Debloat' })
    $u.NavInvestigate.Add_Click({ Show-Page 'Investigate' })
    $u.NavStartup.Add_Click({ Show-Page 'Startup' })
    $u.NavRestore.Add_Click({ Show-Page 'Restore' })

    $u.BtnRefresh.Add_Click({
        $title = $u.PageTitle.Text
        switch ($title) {
            'Security'      { Start-SecurityScan }
            'Debloat'       { Start-BloatScan }
            'Investigate'   { Start-DfirScan }
            'Startup'       { Start-StartupScan }
            'Restore & Logs'{ Update-LogView }
            default         { Start-FullScan }
        }
    })

    $u.BtnFullScan.Add_Click({ Show-Page 'Security'; Start-FullScan })
    $u.BtnSecScan.Add_Click({ Start-SecurityScan })
    $u.BtnSecFixSafe.Add_Click({ Invoke-SecApplyAllSafe })

    # Per-row "Fix" buttons: catch the bubbled Click at the ListView and read Tag=Id.
    $u.SecList.AddHandler(
        [System.Windows.Controls.Button]::ClickEvent,
        [System.Windows.RoutedEventHandler]{
            param($snd,$e)
            $src = $e.OriginalSource
            if ($src -is [System.Windows.Controls.Button] -and $src.Content -eq 'Fix' -and $src.Tag) {
                Invoke-SecFix -Id ([string]$src.Tag)
            }
        }
    )

    $u.BtnBloatScan.Add_Click({ Start-BloatScan })
    $u.BtnBloatSelectRec.Add_Click({ if ($script:State.Bloat) { foreach ($r in $script:State.Bloat) { $r.Selected = [bool]$r.Recommended } } })
    $u.BtnBloatClear.Add_Click({ if ($script:State.Bloat) { foreach ($r in $script:State.Bloat) { $r.Selected = $false } } })
    $u.BtnBloatRemove.Add_Click({ Invoke-BloatRemove })

    $u.BtnDfirScan.Add_Click({ Start-DfirScan })
    $u.BtnDeepScan.Add_Click({ Start-DfirScan -Deep })
    $u.BtnProScan.Add_Click({ Show-ProToolMenu })
    $u.BtnStartupScan.Add_Click({ Start-StartupScan })

    $u.BtnOpenData.Add_Click({ Open-DataFolder })
    $u.BtnOpenRollback.Add_Click({ Open-RollbackScript })
    $u.BtnMakeRestore.Add_Click({ Invoke-MakeRestorePoint })
    $u.BtnRemoveTools.Add_Click({
        $r = [System.Windows.MessageBox]::Show('Delete all downloaded Pro Tools (Hayabusa/Chainsaw)? They can be re-downloaded later.', 'Remove downloaded tools', 'YesNo', 'Question')
        if ($r -eq 'Yes') {
            try { $n = Remove-ExternalTools; [System.Windows.MessageBox]::Show("Removed $n downloaded tool folder(s).", 'Done', 'OK', 'Information') | Out-Null }
            catch { [System.Windows.MessageBox]::Show("Could not remove tools: $($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null }
            Update-LogView
        }
    })
}

# ============================================================================
#  MAIN
# ============================================================================
function Start-Optimizer {
    param([switch]$SelfTest)

    Initialize-Core | Out-Null
    $info = Get-CoreSystemInfo

    $script:UIRef = New-OptimizerWindow
    $script:State = @{ Security=@(); Bloat=$null; Startup=$null; StartupSuppress=$false }

    # header / admin badge
    $script:UIRef.UI.VersionText.Text = "v$($script:Core.Version)  -  Build $($info.Build)"
    if ($info.Admin) {
        $script:UIRef.UI.AdminText.Text = "Administrator - all features available"
        $script:UIRef.UI.AdminText.Foreground = (Get-Brush '#3FB950')
        $script:UIRef.UI.AdminBadge.Background = (Get-Brush '#12210F')
    } else {
        $script:UIRef.UI.AdminText.Text = "Not elevated - scanning works; applying changes needs admin (relaunch via Start.bat)"
        $script:UIRef.UI.AdminText.Foreground = (Get-Brush '#D29922')
    }

    # live log callback -> append to Restore & Logs view on the UI thread
    $script:Core.LogCallback = {
        param($line, $level)
        try {
            $script:UIRef.Window.Dispatcher.Invoke([action]{
                if ($script:UIRef.UI.LogView) {
                    $script:UIRef.UI.LogView.Text += ("`r`n" + $line)
                }
            }, 'Background')
        } catch { }
    }

    Register-Handlers
    Show-Page 'Dashboard'

    if ($SelfTest) {
        # Build + render the window, run read-only scans synchronously, then auto-close.
        Write-CoreLog -Message 'SelfTest: window constructed OK.' -Level OK
        $script:UIRef.Window.Add_ContentRendered({
            try {
                Write-CoreLog -Message 'SelfTest: content rendered.' -Level OK
                $sec = Invoke-SecurityScan;  Write-CoreLog -Message ("SelfTest: security findings = {0}" -f @($sec).Count) -Level INFO
                $inv = Get-DebloatInventory; Write-CoreLog -Message ("SelfTest: removable apps = {0}" -f @($inv).Count) -Level INFO
                $df  = Invoke-DfirTriage;    Write-CoreLog -Message ("SelfTest: dfir findings = {0}" -f @($df).Count) -Level INFO
                $st  = Get-StartupItems;     Write-CoreLog -Message ("SelfTest: startup items = {0}" -f @($st).Count) -Level INFO
                $deep = Invoke-DeepScan;     Write-CoreLog -Message ("SelfTest: deep-scan findings = {0}" -f @($deep).Count) -Level INFO
                # External-tool plumbing (no download/run): registry + consent XAML parse.
                $reg = Get-ExternalToolRegistry; Write-CoreLog -Message ("SelfTest: external tools registered = {0}" -f @($reg).Count) -Level INFO
                $consentOk = $false
                try { $cr = New-Object System.Xml.XmlNodeReader ([xml]$script:ConsentXaml); [void][Windows.Markup.XamlReader]::Load($cr); $consentOk = $true } catch { Write-CoreLog -Message ("SelfTest: consent XAML FAILED: {0}" -f $_.Exception.Message) -Level ERROR }
                Write-Host "SELFTEST_OK findings=$(@($sec).Count) apps=$(@($inv).Count) dfir=$(@($df).Count) startup=$(@($st).Count) deep=$(@($deep).Count) extTools=$(@($reg).Count) consentXaml=$consentOk"
            } catch {
                Write-Host "SELFTEST_FAIL $($_.Exception.Message)"
            } finally {
                $script:CloseTimer = New-Object System.Windows.Threading.DispatcherTimer
                $script:CloseTimer.Interval = [TimeSpan]::FromMilliseconds(400)
                $script:CloseTimer.Add_Tick({ $script:CloseTimer.Stop(); $script:UIRef.Window.Close() })
                $script:CloseTimer.Start()
            }
        })
        [void]$script:UIRef.Window.ShowDialog()
        return
    }

    [void]$script:UIRef.Window.ShowDialog()
}

# ---- entry ----
Start-Optimizer -SelfTest:$SelfTest

