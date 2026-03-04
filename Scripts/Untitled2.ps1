Write-Log -Message "start of script" 
#Set-LogConfiguration -Levels ERROR -EnableDebug
function test_1{
    $var1 = "this is a message inside of a function"
    Write-Log -Var $var1 
    Write-Host $var1 
    Write-Log "writing to host $var1" -Level DEBUG 
    }
function warnFunction{
    $va4= "this is a warn message"
    Write-Log -Var $va4 -Level WARN

    Write-Host $va4
    Write-Log -Message "writing to host $va4" -Level INFO
    }
test_1
warnFunction
Write-Log -Message "end of script" 

